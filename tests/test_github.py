#!/usr/bin/env python3
"""Tests for GitHub repository support. No network: archives are built here.

python3 -m pytest tests/test_github.py
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from srctriage import batch as batch_mod  # noqa: E402
from srctriage import cli as cli_mod  # noqa: E402
from srctriage import github, preflight, puller, secrets  # noqa: E402
from srctriage import verify as verify_mod  # noqa: E402
from srctriage.constants import HISTORY_DIR_NAME, IMAGE_META_NAME  # noqa: E402
from srctriage.extract import ExtractStats, PathFilter  # noqa: E402
from srctriage.reference import folder_name_for, is_repo_ref, parse_repo  # noqa: E402

SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"


def make_tarball(path, entries, sha=SHA, top="octocat-Hello-World-7fd1a60"):
    """Write a tarball shaped like GitHub's: one wrapper folder, sha in pax."""
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": sha}) as tf:
        root = tarfile.TarInfo(top + "/")
        root.type = tarfile.DIRTYPE
        tf.addfile(root)
        for name, kind, data in entries:
            info = tarfile.TarInfo(name if name.startswith(("/", "..")) else f"{top}/{name}")
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                tf.addfile(info)
            else:
                raw = data.encode()
                info.size = len(raw)
                info.mode = 0o755 if kind == "exe" else 0o644
                tf.addfile(info, io.BytesIO(raw))


class TestRecognisingRepositories(unittest.TestCase):
    def test_github_forms_are_repositories(self):
        for raw in (
            "github.com/octocat/Hello-World",
            "https://github.com/octocat/Hello-World",
            "http://www.github.com/octocat/Hello-World",
            "gh:octocat/Hello-World",
            "git@github.com:octocat/Hello-World.git",
        ):
            self.assertTrue(is_repo_ref(raw), raw)

    def test_images_are_not_repositories(self):
        for raw in (
            "alpine:3.19",
            "octocat/hello-world",
            "ghcr.io/octocat/app:1",
            "https://hub.docker.com/r/org/repo",
            "public.ecr.aws/a/b",
        ):
            self.assertFalse(is_repo_ref(raw), raw)


class TestParsingRepositories(unittest.TestCase):
    def test_plain_and_suffixed(self):
        for raw in (
            "github.com/octocat/Hello-World",
            "https://github.com/octocat/Hello-World.git",
            "git@github.com:octocat/Hello-World.git",
            "gh:octocat/Hello-World/",
        ):
            ref = parse_repo(raw)
            self.assertEqual((ref.owner, ref.name, ref.ref), ("octocat", "Hello-World", None), raw)

    def test_refs_from_every_place_people_put_them(self):
        cases = {
            "gh:octocat/Hello-World@v1.2": "v1.2",
            "github.com/octocat/Hello-World@feature/x": "feature/x",
            "gh:o/r@x/tree/y": "x/tree/y",  # everything after @ is the ref, slashes too
            "https://github.com/pallets/flask/tree/3.0.0": "3.0.0",
            f"https://github.com/octocat/Hello-World/commit/{SHA}": SHA,
            "https://github.com/pallets/flask/releases/tag/3.0.0": "3.0.0",
        }
        for raw, want in cases.items():
            self.assertEqual(parse_repo(raw).ref, want, raw)

    def test_ambiguous_and_invalid_forms_are_refused(self):
        for raw in (
            "github.com/octocat",
            "https://github.com/o/r/tree/main/src",  # main/src is also a valid branch
            "https://github.com/o/r/issues/1",
            "gh:o/r/tree/x@y",  # a ref given twice
            "gh:bad owner/r",
        ):
            with self.assertRaises(ValueError, msg=raw):
                parse_repo(raw)

    def test_folder_names_are_stable_and_safe(self):
        self.assertEqual(parse_repo("gh:o/r").folder_name, "github_o_r")
        self.assertEqual(parse_repo("gh:o/r@feature/x").folder_name, "github_o_r_feature_x")
        self.assertEqual(folder_name_for("gh:o/r"), "github_o_r")
        self.assertEqual(folder_name_for("alpine:3.19"), "library_alpine_3.19")

    def test_pretty_is_what_the_record_and_reports_show(self):
        self.assertEqual(parse_repo("gh:o/r@v1").pretty, "github.com/o/r@v1")


class TestExtractingTarballs(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="st-gh-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.archive = os.path.join(self.root, "repo.tar.gz")
        self.dest = os.path.join(self.root, "out")
        os.makedirs(self.dest)

    def test_wrapper_folder_is_dropped_and_sha_recovered(self):
        make_tarball(
            self.archive,
            [("README", "file", "hi"), ("src", "dir", ""), ("src/run.sh", "exe", "echo")],
        )
        stats = ExtractStats()
        sha = github.extract_tarball(self.archive, self.dest, stats)
        self.assertEqual(sha, SHA)
        self.assertEqual(sorted(os.listdir(self.dest)), ["README", "src"])
        self.assertEqual((stats.files, stats.dirs), (2, 1))
        if os.name != "nt":
            self.assertTrue(os.stat(os.path.join(self.dest, "src", "run.sh")).st_mode & 0o100)

    def test_traversal_never_escapes_the_destination(self):
        make_tarball(
            self.archive,
            [("../../evil", "file", "x"), ("ok/../../evil2", "file", "x"), ("fine", "file", "x")],
        )
        stats = ExtractStats()
        github.extract_tarball(self.archive, self.dest, stats)
        self.assertFalse(os.path.exists(os.path.join(self.root, "evil")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "evil2")))
        self.assertTrue(os.path.exists(os.path.join(self.dest, "fine")))
        self.assertGreaterEqual(stats.skipped, 1)

    @unittest.skipIf(os.name == "nt", "symlinks need a privilege on Windows")
    def test_symlinks_stay_links_and_are_never_followed(self):
        make_tarball(self.archive, [("passwd", "sym", "/etc/passwd")])
        stats = ExtractStats()
        github.extract_tarball(self.archive, self.dest, stats)
        link = os.path.join(self.dest, "passwd")
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), "/etc/passwd")
        self.assertEqual(stats.symlinks, 1)

    def test_path_filter_keeps_only_the_wanted_folder(self):
        make_tarball(
            self.archive,
            [("src", "dir", ""), ("src/a.py", "file", "a"), ("docs", "dir", ""), ("x", "file", "")],
        )
        stats = ExtractStats()
        flt = PathFilter(["/src"])
        github.extract_tarball(self.archive, self.dest, stats, flt)
        self.assertEqual(os.listdir(self.dest), ["src"])
        self.assertEqual(flt.match_counts(), {"src": 2})
        self.assertEqual(stats.filtered, 2)


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class TestPullingRepositories(unittest.TestCase):
    """The whole pull, with only the HTTP response faked."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="st-ghpull-")
        self.addCleanup(shutil.rmtree, self.root, True)
        archive = os.path.join(self.root, "src.tar.gz")
        make_tarball(
            archive, [("README", "file", "hello"), ("app", "dir", ""), ("app/x", "file", "1")]
        )
        with open(archive, "rb") as fh:
            self.payload = fh.read()
        self.urls: list[tuple[str, dict]] = []

        def fake_open(url, headers, timeout):
            self.urls.append((url, dict(headers)))
            return _FakeResponse(self.payload)

        patcher = unittest.mock.patch.object(github, "_open", fake_open)
        patcher.start()
        self.addCleanup(patcher.stop)
        env = unittest.mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("GITHUB_TOKEN", None)
        os.environ.pop("GH_TOKEN", None)

    def test_pull_writes_tree_and_a_verifiable_record(self):
        dest = puller.pull("gh:octocat/Hello-World@main", self.root, quiet=True)
        self.assertEqual(os.path.basename(dest), "github_octocat_Hello-World_main")
        record = verify_mod.read_record(dest)
        assert record is not None
        self.assertEqual(record["kind"], "github")
        self.assertEqual(record["image"], "github.com/octocat/Hello-World@main")
        self.assertEqual(record["commit"], SHA)
        self.assertTrue(record["complete"])
        self.assertTrue(verify_mod.verify_dest(dest, quick=False).ok)

    def test_anonymous_downloads_use_codeload_and_send_no_token(self):
        puller.pull("gh:o/r", self.root, quiet=True)
        url, headers = self.urls[0]
        self.assertTrue(url.startswith("https://codeload.github.com/o/r/tar.gz/HEAD"), url)
        self.assertNotIn("Authorization", headers)

    def test_a_token_switches_to_the_api_and_is_sent(self):
        os.environ["GITHUB_TOKEN"] = "t0ken"
        puller.pull("gh:o/r@v1", self.root, quiet=True)
        url, headers = self.urls[0]
        self.assertEqual(url, "https://api.github.com/repos/o/r/tarball/v1")
        self.assertEqual(headers["Authorization"], "Bearer t0ken")

    def test_app_is_refused_for_a_repository(self):
        with self.assertRaises(ValueError):
            puller.pull("gh:o/r", self.root, quiet=True, use_workdir=True)

    def test_a_failed_download_leaves_no_folder_behind(self):
        def missing(url, headers, timeout):
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)  # type: ignore[arg-type]

        with unittest.mock.patch.object(github, "_open", missing):
            with self.assertRaises(RuntimeError):
                puller.pull("gh:o/gone", self.root, quiet=True)
        self.assertFalse(os.path.exists(os.path.join(self.root, "github_o_gone")))

    def test_history_runs_a_bare_clone_into_the_bookkeeping_folder(self):
        calls = []

        def fake_clone(repo, dest, token, timeout=0):
            calls.append((repo.slug, dest))
            os.makedirs(os.path.join(dest, "objects"))

        with unittest.mock.patch.object(github, "clone_history", fake_clone):
            dest = puller.pull("gh:o/r", self.root, quiet=True, history=True)
        self.assertEqual(calls, [("o/r", os.path.join(dest, HISTORY_DIR_NAME))])
        self.assertEqual(verify_mod.read_record(dest)["history"], HISTORY_DIR_NAME)
        # The clone is bookkeeping: a deep verify must not count it.
        self.assertTrue(verify_mod.verify_dest(dest, quick=False).ok)

    def test_verify_list_finds_repository_folders(self):
        puller.pull("gh:o/r", self.root, quiet=True)
        results = verify_mod.verify_list(["gh:o/r", "gh:o/missing"], self.root)
        self.assertEqual([r.ok for r in results], [True, False])


class TestHttpErrorsReadAsReasons(unittest.TestCase):
    def _err(self, code, headers=None):
        return urllib.error.HTTPError("u", code, "m", headers or {}, None)  # type: ignore[arg-type]

    def test_not_found_suggests_a_token_only_when_there_is_none(self):
        repo = parse_repo("gh:o/r")
        self.assertIn("GITHUB_TOKEN", github._explain_http(repo, self._err(404), None))
        self.assertNotIn("GITHUB_TOKEN", github._explain_http(repo, self._err(404), "t"))

    def test_rate_limit_is_named(self):
        msg = github._explain_http(
            parse_repo("gh:o/r"), self._err(403, {"X-RateLimit-Remaining": "0"}), None
        )
        self.assertIn("rate limit", msg)

    def test_preflight_maps_github_answers_to_its_vocabulary(self):
        def head(status):
            def fake(self_, req, timeout=0):
                raise self._err(status)

            return fake

        opener = type(github.urllib.request.build_opener())
        with unittest.mock.patch.object(opener, "open", head(404)):
            self.assertEqual(preflight.check_access("gh:o/r").status, "inaccessible")
            self.assertEqual(preflight.check_access("gh:o/r@nope").status, "missing_tag")
        self.assertEqual(preflight.check_access("gh:o").status, "error")


class TestRedirectDropsTheToken(unittest.TestCase):
    def test_authorization_is_not_forwarded(self):
        import urllib.request

        req = urllib.request.Request(
            "https://api.github.com/x", headers={"Authorization": "Bearer t"}
        )
        new = github._NoAuthOnRedirect().redirect_request(
            req, None, 302, "Found", {}, "https://codeload.github.com/x"
        )
        assert new is not None
        self.assertFalse(new.has_header("Authorization"))


class TestBatchesMixImagesAndRepositories(unittest.TestCase):
    def test_a_repository_only_list_skips_the_docker_hub_budget(self):
        root = tempfile.mkdtemp(prefix="st-ghbatch-")
        self.addCleanup(shutil.rmtree, root, True)
        seen = []

        def fake_pull(image, out_dir, **kw):
            seen.append((image, kw.get("history")))
            dest = os.path.join(out_dir, folder_name_for(image))
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "f"), "w") as fh:
                fh.write("x")
            verify_mod.write_record(
                dest,
                {
                    "image": image,
                    "layers": [{"digest": "git:x"}],
                    "rootfs": verify_mod.scan_tree(dest).as_dict(),
                    "complete": True,
                },
            )
            return dest

        def no_budget():
            raise AssertionError("Docker Hub budget checked for a repository-only list")

        with (
            unittest.mock.patch.object(puller, "pull", fake_pull),
            unittest.mock.patch.object(batch_mod.ratelimit, "check_rate_budget", no_budget),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            results = batch_mod.pull_many(
                ["gh:o/a", "gh:o/b"], root, check_access=False, history=True
            )
        self.assertTrue(all(r.ok for r in results))
        self.assertEqual(seen, [("gh:o/a", True), ("gh:o/b", True)])


class TestCli(unittest.TestCase):
    def test_bare_repository_routes_to_pull_with_history(self):
        seen = {}

        def fake(image, output, **kw):
            seen["image"] = image
            seen.update(kw)
            return "/tmp/x"

        with (
            unittest.mock.patch.object(puller, "pull", fake),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            rc = cli_mod.main(["github.com/o/r", "-H", "-q", "-X"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen["image"], "github.com/o/r")
        self.assertTrue(seen["history"])

    def test_history_on_an_image_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli_mod.main(["alpine:3.19", "--history", "-q"]), 2)

    def test_inspect_digests_prints_the_commit(self):
        out = io.StringIO()
        with (
            unittest.mock.patch.object(github, "resolve_commit", lambda ref: SHA),
            contextlib.redirect_stdout(out),
        ):
            rc = cli_mod.main(["inspect", "-D", "gh:o/r"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue().strip(), SHA)

    def test_inspect_shows_repository_details(self):
        info = {
            "repository": "o/r",
            "ref": "main",
            "description": "a thing",
            "visibility": "public",
            "size_kb": 2,
            "language": "Python",
            "archived": False,
            "pushed_at": "2026-01-01",
            "clone_url": "https://github.com/o/r.git",
        }
        out = io.StringIO()
        with (
            unittest.mock.patch.object(github, "describe", lambda ref: info),
            contextlib.redirect_stdout(out),
        ):
            rc = cli_mod.main(["inspect", "gh:o/r"])
        self.assertEqual(rc, 0)
        self.assertIn("a thing", out.getvalue())


class TestHistoryIsScannedAsCommits(unittest.TestCase):
    """A deleted credential is still in history; the scan must say so."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="st-ghsec-")
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(os.path.join(self.root, HISTORY_DIR_NAME, "objects"))
        with open(os.path.join(self.root, "README"), "w") as fh:
            fh.write("clean\n")
        with open(os.path.join(self.root, IMAGE_META_NAME), "w") as fh:
            json.dump({"image": "github.com/o/r", "complete": True}, fh)

    def test_engines_run_in_git_mode_and_findings_carry_the_commit(self):
        calls = []

        def fake_run(cmd, timeout):
            calls.append(cmd)
            out = "[]"
            if "git" in cmd[1:2]:
                out = json.dumps(
                    [
                        {
                            "RuleID": "stripe-access-token",
                            "Secret": "sk_live_deleted",
                            "File": "config.py",
                            "StartLine": 3,
                            "Commit": "abc123def4567890",
                            "MatchContext": 'KEY = "sk_live_deleted"',
                        }
                    ]
                )
            return unittest.mock.Mock(stdout=out)

        with (
            unittest.mock.patch.object(secrets.Engine, "available", lambda self: "/bin/x"),
            unittest.mock.patch.object(secrets, "_run", fake_run),
        ):
            result = secrets.scan_tree_for_secrets(self.root, engines=[secrets.BETTERLEAKS])

        modes = [c[1] for c in calls]
        self.assertEqual(modes, ["dir", "git"])
        self.assertEqual(calls[1][2], os.path.join(self.root, HISTORY_DIR_NAME))
        [finding] = result.findings
        self.assertEqual(finding.source, "git-history")
        self.assertEqual(finding.commit, "abc123def4567890")
        self.assertIn("@ abc123def456", finding.location)
        self.assertTrue(any("git history" in n for n in result.coverage.notes))

    def test_the_object_store_is_not_walked_as_files(self):
        rels = [rel for _, rel in secrets._iter_files(self.root)]
        self.assertFalse([r for r in rels if r.startswith(HISTORY_DIR_NAME)])

    def test_trufflehog_git_output_is_read(self):
        line = json.dumps(
            {
                "Raw": "AKIAXXXXXXXXXXXXXXXX",
                "DetectorName": "AWS",
                "SourceMetadata": {"Data": {"Git": {"file": "keys", "line": 4, "commit": "fbc1"}}},
            }
        )
        [f] = secrets._read_trufflehog_json(line, self.root, "img", "git-history")
        self.assertEqual((f.path, f.line, f.commit, f.source), ("keys", 4, "fbc1", "git-history"))


class TestPemKeysAreNotComments(unittest.TestCase):
    def test_a_private_key_header_is_not_an_sql_comment(self):
        line = "-----BEGIN OPENSSH PRIVATE KEY-----"
        self.assertFalse(secrets.is_commented_out(line, line))
        self.assertTrue(secrets.is_commented_out("-- password = 'hunter22'", "hunter22"))


if __name__ == "__main__":
    unittest.main()
