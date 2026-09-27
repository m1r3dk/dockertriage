#!/usr/bin/env python3
"""Tests for secret extraction.

The detection engines are external binaries, so these pin the parts we own:
the gap-fillers the engines were measured to miss, the merge, the coverage
accounting, and the report layout. Nothing here needs an engine installed.

    python3 -m pytest tests/test_secrets.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from dockertriage import secretreport, secrets  # noqa: E402


class TestNamedSecretVariables(unittest.TestCase):
    """The measured gap: a credential named by its variable, not its shape.

    Every external engine missed `DB_PASSWORD=hunter2`, because `hunter2`
    looks like nothing. The name is the evidence.
    """

    def _secrets(self, name, value):
        return [f.secret for f in secrets.secret_env_findings(name, value, "p", "img", "test")]

    def test_a_shapeless_password_is_found_by_its_name(self):
        self.assertEqual(self._secrets("DB_PASSWORD", "hunter2"), ["hunter2"])

    def test_every_credential_naming_convention_is_covered(self):
        for name in (
            "DB_PASSWORD",
            "SECRET_KEY_BASE",
            "API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "CLIENT_SECRET",
            "DATABASE_URL",
            "auth_token",
            "private-key",
        ):
            self.assertTrue(self._secrets(name, "s0me-real-value"), f"{name} was not recognised")

    def test_an_ordinary_variable_is_not_a_finding(self):
        for name in ("PATH", "NODE_VERSION", "HOME", "LANG", "PORT"):
            self.assertEqual(self._secrets(name, "/usr/bin"), [], name)

    def test_placeholders_are_not_reported(self):
        """A report full of 'changeme' buries the real findings."""
        for value in (
            "changeme",
            "your_password_here",
            "xxxxxx",
            "<password>",
            "${DB_PASSWORD}",
            "placeholder",
            "TODO",
            "null",
        ):
            self.assertEqual(self._secrets("DB_PASSWORD", value), [], value)

    def test_a_path_is_not_a_secret(self):
        """Real images set DATABASE_URL to a file path; that is not a leak."""
        self.assertEqual(self._secrets("DATABASE_URL", "file:/data/app.db"), [])
        self.assertEqual(self._secrets("DATABASE_URL", "/var/lib/app.db"), [])

    def test_a_url_without_credentials_is_not_a_secret(self):
        self.assertEqual(self._secrets("DATABASE_URL", "postgres://db:5432/app"), [])

    def test_a_url_with_credentials_is_a_secret(self):
        found = self._secrets("DATABASE_URL", "postgres://admin:s3cret@db:5432/app")
        self.assertEqual(len(found), 1)

    def test_a_value_too_short_to_be_a_credential_is_ignored(self):
        self.assertEqual(self._secrets("API_KEY", "x"), [])


class TestImageConfigIsRead(unittest.TestCase):
    """The half of an image that is configuration, not files."""

    def test_env_credentials_are_found(self):
        record = {
            "config": {
                "Env": [
                    "PATH=/usr/bin",
                    "DB_PASSWORD=pr0d-db-p@ss",
                    "NODE_VERSION=22.1.0",
                ]
            }
        }
        findings, listing = secrets.scan_image_config(record, "img")
        self.assertEqual([f.secret for f in findings], ["pr0d-db-p@ss"])
        # The listing keeps everything: a responder reading one variable
        # usually wants to see its neighbours.
        self.assertEqual(len(listing), 3)

    def test_a_credential_passed_as_a_command_flag_is_found(self):
        record = {"config": {"Cmd": ["node", "server.js", "--api-key=live_9f8e7d6c"]}}
        findings, _ = secrets.scan_image_config(record, "img")
        self.assertEqual([f.secret for f in findings], ["live_9f8e7d6c"])

    def test_findings_are_marked_as_coming_from_the_config(self):
        record = {"config": {"Env": ["SECRET_KEY=abcdef123456"]}}
        findings, _ = secrets.scan_image_config(record, "img")
        self.assertEqual(findings[0].source, "image-config")

    def test_a_record_without_config_is_not_an_error(self):
        findings, listing = secrets.scan_image_config({}, "img")
        self.assertEqual((findings, listing), ([], []))


class TestCredentialFilesByName(unittest.TestCase):
    """Files that are credentials whatever an engine makes of the bytes.

    An `.npmrc` token was missed by all three Go engines, so name-based
    detection is not redundant with them.
    """

    def test_the_usual_credential_files_are_recognised(self):
        for path, expected in (
            ("app/.env", "environment file"),
            ("app/.env.production", "environment file"),
            ("root/.npmrc", "npm registry token file"),
            ("root/.aws/credentials", "cloud or service credentials file"),
            ("root/.ssh/id_rsa", "private SSH key"),
            ("etc/ssl/server.key", "private key"),
            ("app/keystore.jks", "Java keystore"),
            ("root/.docker/config.json", "docker registry credentials"),
        ):
            self.assertEqual(secrets.credential_file_reason(path), expected, path)

    def test_an_ordinary_file_is_not_flagged(self):
        for path in ("app/main.py", "README.md", "etc/hostname", "app/config.json"):
            self.assertEqual(secrets.credential_file_reason(path), "", path)


class TestMergingFindings(unittest.TestCase):
    """Two engines reporting one leak is one finding, not two."""

    def _finding(self, **kw):
        base = {
            "rule": "r",
            "description": "d",
            "severity": "high",
            "secret": "s3cret",
            "path": "app/.env",
            "line": 1,
        }
        base.update(kw)
        return secrets.Finding(**base)

    def test_the_same_secret_in_the_same_place_collapses(self):
        merged = secrets.merge_findings(
            [self._finding(engine="betterleaks"), self._finding(engine="gitleaks")]
        )
        self.assertEqual(len(merged), 1)

    def test_agreement_between_engines_is_recorded(self):
        merged = secrets.merge_findings(
            [self._finding(engine="betterleaks"), self._finding(engine="gitleaks")]
        )
        self.assertEqual(merged[0].engine, "betterleaks+gitleaks")

    def test_the_same_secret_in_two_files_stays_two_findings(self):
        """Both copies have to be fixed, so both must be reported."""
        merged = secrets.merge_findings(
            [self._finding(path="a/.env"), self._finding(path="b/.env")]
        )
        self.assertEqual(len(merged), 2)

    def test_a_verified_credential_wins_over_an_unverified_one(self):
        merged = secrets.merge_findings(
            [self._finding(verified=None), self._finding(verified=True, engine="trufflehog")]
        )
        self.assertIs(merged[0].verified, True)

    def test_the_worst_severity_wins(self):
        merged = secrets.merge_findings(
            [self._finding(severity="medium"), self._finding(severity="critical")]
        )
        self.assertEqual(merged[0].severity, "critical")

    def test_critical_findings_sort_first(self):
        merged = secrets.merge_findings(
            [
                self._finding(secret="a", severity="medium", path="z"),
                self._finding(secret="b", severity="critical", path="z"),
            ]
        )
        self.assertEqual(merged[0].severity, "critical")


class TestCoverageIsHonest(unittest.TestCase):
    """An engine that never ran is the blind spot that matters most."""

    def test_a_missing_engine_makes_coverage_incomplete(self):
        cov = secrets.ScanCoverage(engines_missing=["betterleaks"])
        self.assertFalse(cov.complete)

    def test_a_missing_engine_is_stated_plainly(self):
        cov = secrets.ScanCoverage(engines_missing=["betterleaks"])
        text = " ".join(cov.lines())
        self.assertIn("NOT INSTALLED", text)
        self.assertIn("betterleaks", text)

    def test_an_unscanned_path_makes_coverage_incomplete(self):
        cov = secrets.ScanCoverage()
        cov.note_unscanned("app/lib.jar", "archive")
        self.assertFalse(cov.complete)

    def test_a_full_run_reports_complete(self):
        cov = secrets.ScanCoverage(files_seen=3, engines_run=["betterleaks"])
        self.assertTrue(cov.complete)
        self.assertIn("every engine ran", " ".join(cov.lines()))

    def test_merging_keeps_every_missing_engine_once(self):
        a = secrets.ScanCoverage(engines_missing=["trufflehog"], files_seen=1)
        b = secrets.ScanCoverage(engines_missing=["trufflehog"], files_seen=2)
        a.merge(b)
        self.assertEqual(a.engines_missing, ["trufflehog"])
        self.assertEqual(a.files_seen, 3)


class TestScanningATree(unittest.TestCase):
    """End to end, with no engine installed: the floor must still hold."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-secrets-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _scan(self):
        # engines=[] means "run none", so the test pins our own detection
        # rather than whatever happens to be installed on the machine.
        return secrets.scan_tree_for_secrets(self.root, engines=[])

    def test_an_env_file_credential_is_found_without_any_engine(self):
        self._write("app/.env", "DB_PASSWORD=hunter2\n")
        result = self._scan()
        self.assertIn("hunter2", [f.secret for f in result.findings])

    def test_the_line_number_is_reported(self):
        self._write("app/.env", "# comment\nFOO=bar\nAPI_KEY=abc123def456\n")
        finding = next(f for f in self._scan().findings if f.secret == "abc123def456")
        self.assertEqual(finding.line, 3)

    def test_image_config_env_is_read_from_the_record(self):
        self._write(
            ".image.json",
            json.dumps(
                {
                    "image": "example/app:1.0",
                    "complete": True,
                    "config": {"Env": ["SECRET_KEY=s0mething-real"]},
                }
            ),
        )
        result = self._scan()
        self.assertIn("s0mething-real", [f.secret for f in result.findings])
        self.assertEqual(result.image, "example/app:1.0")

    def test_credential_files_are_listed_even_when_nothing_matches(self):
        """An empty-looking keystore is still a credential file."""
        self._write("root/.ssh/id_rsa", "")
        result = self._scan()
        self.assertEqual([c["path"] for c in result.credential_files], ["root/.ssh/id_rsa"])

    def test_an_archive_is_recorded_as_unscanned_not_as_clean(self):
        self._write("app/lib.jar", "PK\x03\x04 pretend jar")
        result = self._scan()
        reasons = [u["reason"] for u in result.coverage.unscanned if "lib.jar" in u["path"]]
        self.assertTrue(reasons, "an unopened archive was treated as clean")
        self.assertIn("archive", reasons[0])

    def test_running_no_engines_is_stated_in_the_coverage_notes(self):
        self._write("app/main.py", "x = 1\n")
        result = self._scan()
        self.assertTrue(any("No external engine ran" in n for n in result.coverage.notes))

    def test_a_symlink_out_of_the_tree_is_not_followed(self):
        """A link to / would otherwise walk the whole host filesystem."""
        os.symlink("/", os.path.join(self.root, "escape"))
        result = self._scan()
        self.assertLess(result.coverage.files_seen, 50)


class TestDiscoveringTargets(unittest.TestCase):
    """`dt secrets .` has to mean the right thing in three situations."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-secrets-t-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _image(self, name):
        path = os.path.join(self.root, name)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, ".image.json"), "w", encoding="utf-8") as fh:
            json.dump({"image": name, "complete": True}, fh)
        return path

    def test_an_extracted_image_is_one_target(self):
        image = self._image("alpine")
        self.assertEqual(secrets.discover_targets(image), [image])

    def test_a_folder_of_images_becomes_one_target_each(self):
        self._image("one")
        self._image("two")
        found = secrets.discover_targets(self.root)
        self.assertEqual(len(found), 2)

    def test_an_ordinary_directory_is_scanned_whole(self):
        """`dt secrets .` in a source checkout must scan the checkout."""
        os.makedirs(os.path.join(self.root, "src"), exist_ok=True)
        self.assertEqual(
            secrets.discover_targets(self.root), [os.path.abspath(self.root)]
        )


class TestReportLayout(unittest.TestCase):
    """The output folder is what someone acts from, so its shape is pinned."""

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="dt-secrets-out-")
        self.addCleanup(shutil.rmtree, self.out, True)
        self.src = tempfile.mkdtemp(prefix="dt-secrets-src-")
        self.addCleanup(shutil.rmtree, self.src, True)

        result = secrets.ScanResult(image="example/app:1.0", root=self.src)
        result.findings = [
            secrets.Finding(
                rule="aws-access-token",
                description="AWS key",
                severity="critical",
                secret="AKIAZ4XY7QWERTYUIOPA",
                path="root/.aws/credentials",
                line=2,
                image="example/app:1.0",
            ),
            secrets.Finding(
                rule="named-secret-variable",
                description="DB_PASSWORD names a credential",
                severity="critical",
                secret="hunter2",
                path=".image.json (config.Env)",
                source="image-config",
                image="example/app:1.0",
            ),
        ]
        result.env = [{"name": "DB_PASSWORD", "value": "hunter2"}]
        result.coverage.files_seen = 4
        result.coverage.engines_run = ["betterleaks"]
        result.coverage.engines_missing = ["trufflehog"]
        self.scan = secrets.SecretScan(results=[result])
        self.base = secretreport.write_report(self.scan, self.out)

    def _read(self, *parts):
        with open(os.path.join(self.base, *parts), encoding="utf-8") as fh:
            return fh.read()

    def test_the_expected_files_are_written(self):
        for rel in ("findings.json", "SUMMARY.md", "UNSCANNED.md"):
            self.assertTrue(os.path.exists(os.path.join(self.base, rel)), rel)

    def test_secrets_are_written_in_the_clear(self):
        """Reveal by default: a masked report cannot be acted on."""
        self.assertIn("AKIAZ4XY7QWERTYUIOPA", self._read("findings.json"))
        self.assertIn("hunter2", self._read("findings.json"))

    def test_the_summary_warns_what_the_folder_holds(self):
        text = self._read("SUMMARY.md")
        self.assertIn("live credential", text.lower())

    def test_a_missing_engine_is_named_in_the_summary(self):
        self.assertIn("trufflehog", self._read("SUMMARY.md"))

    def test_unscanned_explains_which_engines_never_ran(self):
        text = self._read("UNSCANNED.md")
        self.assertIn("trufflehog", text)
        self.assertIn("never ran", text.lower())

    def test_findings_are_grouped_by_type_for_bulk_rotation(self):
        self.assertTrue(os.path.exists(os.path.join(self.base, "by-type", "aws.json")))

    def test_each_image_gets_its_own_folder(self):
        folder = os.path.join(self.base, "by-image", "example_app_1.0")
        self.assertTrue(os.path.isdir(folder), os.listdir(os.path.join(self.base, "by-image")))
        self.assertTrue(os.path.exists(os.path.join(folder, "findings.json")))

    def test_the_environment_is_written_out_in_full(self):
        self.assertIn("DB_PASSWORD=hunter2", self._read("by-image", "example_app_1.0", "env.txt"))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits only")
    def test_the_folder_is_owner_only(self):
        """A credential dump must not be world-readable."""
        self.assertEqual(os.stat(self.base).st_mode & 0o777, 0o700)
        path = os.path.join(self.base, "findings.json")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_an_empty_scan_still_warns_about_uninstalled_engines(self):
        """No findings and no scanner look identical without this."""
        empty = secrets.SecretScan(
            results=[
                secrets.ScanResult(
                    image="clean",
                    root=self.src,
                    coverage=secrets.ScanCoverage(engines_missing=["betterleaks"]),
                )
            ]
        )
        out = tempfile.mkdtemp(prefix="dt-secrets-empty-")
        self.addCleanup(shutil.rmtree, out, True)
        base = secretreport.write_report(empty, out)
        with open(os.path.join(base, "SUMMARY.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("UNSCANNED.md", text)
        self.assertIn("betterleaks", text)


class TestEngineOutputParsing(unittest.TestCase):
    """Engine adapters, pinned against the real schemas they emit."""

    def test_betterleaks_json_is_understood(self):
        raw = json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS key",
                    "Secret": "AKIAZ4XY7QWERTYUIOPA",
                    "File": "root/.aws/credentials",
                    "StartLine": 2,
                    "Match": "aws_access_key_id = AKIAZ4XY7QWERTYUIOPA",
                }
            ]
        )
        found = secrets._read_leaks_json(raw, "betterleaks", "/img", "i")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].secret, "AKIAZ4XY7QWERTYUIOPA")
        self.assertEqual(found[0].severity, "critical")

    def test_trufflehog_jsonl_is_understood(self):
        raw = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": "app/.env", "line": 3}}},
                "DetectorName": "Postgres",
                "Raw": "postgres://admin:s3cret@db:5432",
                "Verified": True,
            }
        )
        found = secrets._read_trufflehog_json(raw, "/img", "i")
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].verified, True)
        # A credential proven live is not a maybe.
        self.assertEqual(found[0].severity, "critical")

    def test_malformed_engine_output_is_not_a_crash(self):
        self.assertEqual(secrets._read_leaks_json("not json", "betterleaks", "/i", "x"), [])
        self.assertEqual(secrets._read_trufflehog_json("not json", "/i", "x"), [])

    def test_an_engine_finding_in_the_record_is_marked_image_config(self):
        raw = json.dumps(
            [{"RuleID": "generic-api-key", "Secret": "abc", "File": ".image.json", "StartLine": 1}]
        )
        found = secrets._read_leaks_json(raw, "gitleaks", "/img", "i")
        self.assertEqual(found[0].source, "image-config")


if __name__ == "__main__":
    unittest.main(verbosity=2)
