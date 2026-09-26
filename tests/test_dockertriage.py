#!/usr/bin/env python3
"""Tests for the dockertriage core — no network required.

The CLI has its own suite in tests/test_cli.py; everything here targets the
library modules directly, which is why this file imports no typer.

    python3 -m pytest tests/
    python3 tests/test_dockertriage.py
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import dockertriage as dp
from dockertriage import batch as batch_mod
from dockertriage import coverage as coverage_mod
from dockertriage import preflight as preflight_mod
from dockertriage import puller as puller_mod
from dockertriage import ratelimit as ratelimit_mod
from dockertriage import tags as tags_mod
from dockertriage.humanize import build_step, human_bytes, one_line, short_digest


class TestOneLine(unittest.TestCase):
    """buildkit commands arrive full of tabs and newlines."""

    def test_collapses_tabs_and_newlines_to_single_spaces(self):
        raw = "RUN /bin/sh -c set -eux; \t\tapt-get update; \n\tapt-get install -y foo"
        got = one_line(raw)
        self.assertNotIn("\t", got)
        self.assertNotIn("\n", got)
        self.assertNotIn("  ", got)
        self.assertEqual(got, "RUN /bin/sh -c set -eux; apt-get update; apt-get install -y foo")

    def test_truncates_with_an_ellipsis_at_the_width(self):
        got = one_line("x" * 200, width=20)
        self.assertEqual(len(got), 20)
        self.assertTrue(got.endswith("…"))

    def test_short_command_is_untouched(self):
        self.assertEqual(one_line("WORKDIR /app"), "WORKDIR /app")


class TestHumanBytes(unittest.TestCase):
    def test_scales_units(self):
        self.assertEqual(human_bytes(512), "512B")
        self.assertEqual(human_bytes(1536), "1.5KB")
        self.assertEqual(human_bytes(5 * 1024 * 1024), "5.0MB")


def make_layer(entries) -> io.BytesIO:
    """entries: list of (name, kind, payload). kind in f/d/l/h/wh."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, payload in entries:
            if kind == "d":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "l":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            elif kind == "h":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tf.addfile(ti)
            else:  # regular file (including .wh. markers)
                data = (payload or "").encode()
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
    buf.seek(0)
    return buf


class TempRoot(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-test-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def apply(self, entries) -> dp.ExtractStats:
        stats = dp.ExtractStats()
        dp.extract_layer(make_layer(entries), self.root, stats)
        return stats

    def p(self, rel: str) -> str:
        return os.path.join(self.root, rel.replace("/", os.sep))


class TestParsing(unittest.TestCase):
    def test_bare_name_gets_library_prefix(self):
        img = dp.parse_image("alpine")
        self.assertEqual(img.repo, "library/alpine")
        self.assertEqual(img.ref, "latest")

    def test_tag(self):
        img = dp.parse_image("alpine:3.19")
        self.assertEqual((img.repo, img.ref), ("library/alpine", "3.19"))

    def test_namespaced(self):
        img = dp.parse_image("grafana/grafana:11.0.0")
        self.assertEqual((img.repo, img.ref), ("grafana/grafana", "11.0.0"))

    def test_digest(self):
        img = dp.parse_image("alpine@sha256:" + "a" * 64)
        self.assertTrue(img.is_digest)
        self.assertEqual(img.ref, "sha256:" + "a" * 64)

    def test_docker_io_prefix_stripped(self):
        self.assertEqual(dp.parse_image("docker.io/library/nginx").repo, "library/nginx")
        self.assertEqual(dp.parse_image("index.docker.io/grafana/loki").repo, "grafana/loki")

    def test_hub_url(self):
        img = dp.parse_image("https://hub.docker.com/r/grafana/grafana")
        self.assertEqual(img.repo, "grafana/grafana")

    def test_hub_url_official(self):
        img = dp.parse_image("https://hub.docker.com/_/redis")
        self.assertEqual(img.repo, "library/redis")

    def test_hub_url_with_tag_query(self):
        img = dp.parse_image("https://hub.docker.com/r/grafana/grafana?tag=11.0.0")
        self.assertEqual(img.ref, "11.0.0")

    def test_bare_hub_host_without_scheme(self):
        img = dp.parse_image("hub.docker.com/r/org/app")
        self.assertEqual(img.repo, "org/app")

    def test_ecr_public(self):
        img = dp.parse_image("public.ecr.aws/nginx/nginx:latest")
        self.assertEqual((img.registry, img.repo), ("ecr_public", "nginx/nginx"))

    def test_ecr_nested_repo_keeps_all_segments(self):
        """ECR repo names can nest: registry-alias/name/sub."""
        img = dp.parse_image("public.ecr.aws/flakybitnet/blocky/agh-data")
        self.assertEqual(img.repo, "flakybitnet/blocky/agh-data")

    def test_ecr_gallery_url_nested_repo(self):
        img = dp.parse_image("https://gallery.ecr.aws/flakybitnet/blocky/agh-data")
        self.assertEqual(img.repo, "flakybitnet/blocky/agh-data")

    def test_gallery_url_digest_query_is_honoured(self):
        """?digest=... must pin the image, not silently fall back to latest."""
        digest = "sha256:" + "5" * 64
        img = dp.parse_image(f"https://gallery.ecr.aws/flakybitnet/blocky/agh-data?digest={digest}")
        self.assertEqual(img.repo, "flakybitnet/blocky/agh-data")
        self.assertEqual(img.ref, digest)
        self.assertTrue(img.is_digest)

    def test_hub_url_digest_query_is_honoured(self):
        digest = "sha256:" + "a" * 64
        img = dp.parse_image(f"https://hub.docker.com/r/grafana/grafana?digest={digest}")
        self.assertEqual(img.ref, digest)
        self.assertTrue(img.is_digest)

    def test_query_tag_still_works_alongside_digest_support(self):
        img = dp.parse_image("https://hub.docker.com/r/grafana/grafana?tag=11.0.0")
        self.assertEqual(img.ref, "11.0.0")
        self.assertFalse(img.is_digest)

    def test_pretty_uses_at_for_digests(self):
        digest = "sha256:" + "b" * 64
        img = dp.parse_image(f"alpine@{digest}")
        self.assertEqual(img.pretty, f"library/alpine@{digest}")

    def test_pretty_uses_colon_for_tags(self):
        img = dp.parse_image("alpine:3.19")
        self.assertEqual(img.pretty, "library/alpine:3.19")

    def test_digest_folder_name_is_readable(self):
        img = dp.parse_image(
            "https://gallery.ecr.aws/flakybitnet/blocky/agh-data?digest=sha256:"
            + "5638708e40b24cc9"
            + "0" * 48
        )
        self.assertEqual(img.folder_name, "flakybitnet_blocky_agh-data_5638708e40b24cc9")

    def test_ecr_gallery_url(self):
        img = dp.parse_image("https://gallery.ecr.aws/nginx/nginx")
        self.assertEqual((img.registry, img.repo), ("ecr_public", "nginx/nginx"))

    def test_folder_name_is_filesystem_safe(self):
        img = dp.parse_image("grafana/grafana:11.0.0")
        self.assertEqual(img.folder_name, "grafana_grafana_11.0.0")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            dp.parse_image("   ")

    def test_rejects_unknown_host(self):
        with self.assertRaises(ValueError):
            dp.parse_image("https://quay.io/org/app")


class TestPathSafety(unittest.TestCase):
    def test_safe_relpath_rejects_traversal(self):
        self.assertIsNone(dp.safe_relpath("../etc/passwd"))
        self.assertIsNone(dp.safe_relpath(".."))
        self.assertIsNone(dp.safe_relpath("/"))
        self.assertIsNone(dp.safe_relpath(""))

    def test_safe_relpath_strips_leading_slash(self):
        self.assertEqual(dp.safe_relpath("/etc/passwd"), "etc/passwd")

    def test_safe_join_blocks_escape(self):
        with self.assertRaises(ValueError):
            dp.safe_join("/tmp/root", "../escape")

    def test_safe_join_blocks_sibling_prefix(self):
        # /tmp/rootevil must not be accepted as inside /tmp/root
        with self.assertRaises(ValueError):
            dp.safe_join("/tmp/root", "../rootevil/x")


class TestExtraction(TempRoot):
    def test_regular_file(self):
        self.apply([("etc/hostname", "f", "box")])
        with open(self.p("etc/hostname")) as fh:
            self.assertEqual(fh.read(), "box")

    def test_extracted_files_are_writable(self):
        """Read-only output would make the folder painful to delete or edit."""
        self.apply([("etc/hostname", "f", "box")])
        self.assertTrue(os.access(self.p("etc/hostname"), os.W_OK))

    def test_symlink_preserved(self):
        stats = self.apply([("bin/busybox", "f", "ELF"), ("bin/sh", "l", "busybox")])
        self.assertEqual(stats.symlinks, 1)
        self.assertTrue(os.path.islink(self.p("bin/sh")))
        self.assertEqual(os.readlink(self.p("bin/sh")), "busybox")

    def test_absolute_symlink_preserved_verbatim(self):
        self.apply([("usr/bin/python", "l", "/usr/local/bin/python3.12")])
        self.assertEqual(os.readlink(self.p("usr/bin/python")), "/usr/local/bin/python3.12")

    def test_dangling_symlink_still_created(self):
        stats = self.apply([("link", "l", "nowhere/at/all")])
        self.assertEqual(stats.symlinks, 1)
        self.assertTrue(os.path.islink(self.p("link")))

    def test_hardlink_materialized(self):
        stats = self.apply([("a.txt", "f", "same"), ("b.txt", "h", "a.txt")])
        self.assertEqual(stats.hardlinks, 1)
        with open(self.p("b.txt")) as fh:
            self.assertEqual(fh.read(), "same")

    def test_link_target_later_in_tar(self):
        """Links are deferred, so ordering inside a layer must not matter."""
        stats = self.apply([("b.txt", "h", "a.txt"), ("a.txt", "f", "payload")])
        self.assertEqual(stats.hardlinks, 1)
        with open(self.p("b.txt")) as fh:
            self.assertEqual(fh.read(), "payload")

    def test_traversal_member_skipped_not_written(self):
        stats = self.apply([("../evil.txt", "f", "pwned"), ("ok.txt", "f", "fine")])
        self.assertEqual(stats.skipped, 1)
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.root), "evil.txt")))
        self.assertTrue(os.path.exists(self.p("ok.txt")))

    def test_absolute_path_member_confined_to_root(self):
        self.apply([("/etc/shadow", "f", "nope")])
        self.assertTrue(os.path.exists(self.p("etc/shadow")))

    def test_symlink_escape_not_followed_on_overwrite(self):
        """A symlink to outside the root must be replaced, not written through."""
        outside = os.path.join(os.path.dirname(self.root), "dp-outside.txt")
        with open(outside, "w") as fh:
            fh.write("original")
        try:
            self.apply([("escape", "l", outside)])
            self.apply([("escape", "f", "overwritten")])
            with open(outside) as fh:
                self.assertEqual(fh.read(), "original")
            self.assertFalse(os.path.islink(self.p("escape")))
        finally:
            os.remove(outside)


class TestWhiteouts(TempRoot):
    def test_file_whiteout_removes_file(self):
        self.apply([("app/secret.env", "f", "TOKEN=abc")])
        self.assertTrue(os.path.exists(self.p("app/secret.env")))
        stats = self.apply([("app/.wh.secret.env", "f", "")])
        self.assertEqual(stats.whiteouts, 1)
        self.assertFalse(os.path.exists(self.p("app/secret.env")))

    def test_whiteout_marker_never_lands_in_output(self):
        self.apply([("app/x", "f", "1")])
        self.apply([("app/.wh.x", "f", "")])
        self.assertFalse(os.path.exists(self.p("app/.wh.x")))
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for name in filenames:
                self.assertFalse(name.startswith(".wh."), f"leaked {dirpath}/{name}")

    def test_directory_whiteout_removes_tree(self):
        self.apply([("cache/a", "f", "1"), ("cache/sub/b", "f", "2")])
        self.apply([(".wh.cache", "f", "")])
        self.assertFalse(os.path.exists(self.p("cache")))

    def test_opaque_whiteout_clears_inherited_contents(self):
        self.apply([("data/old1", "f", "1"), ("data/old2", "f", "2")])
        self.apply([("data/.wh..wh..opq", "f", ""), ("data/new", "f", "3")])
        self.assertFalse(os.path.exists(self.p("data/old1")))
        self.assertFalse(os.path.exists(self.p("data/old2")))
        self.assertTrue(os.path.exists(self.p("data/new")))

    def test_whiteout_of_symlink(self):
        self.apply([("bin/sh", "l", "busybox")])
        self.apply([("bin/.wh.sh", "f", "")])
        self.assertFalse(os.path.lexists(self.p("bin/sh")))

    def test_deleted_then_recreated_across_layers(self):
        self.apply([("f", "f", "v1")])
        self.apply([(".wh.f", "f", "")])
        self.apply([("f", "f", "v2")])
        with open(self.p("f")) as fh:
            self.assertEqual(fh.read(), "v2")


class TestLayerMerge(TempRoot):
    def test_later_layer_overwrites_file(self):
        self.apply([("etc/conf", "f", "old")])
        self.apply([("etc/conf", "f", "new")])
        with open(self.p("etc/conf")) as fh:
            self.assertEqual(fh.read(), "new")

    def test_file_replaced_by_directory(self):
        self.apply([("thing", "f", "iam-a-file")])
        self.apply([("thing", "d", None), ("thing/inner", "f", "x")])
        self.assertTrue(os.path.isdir(self.p("thing")))
        self.assertTrue(os.path.exists(self.p("thing/inner")))

    def test_directory_replaced_by_file(self):
        self.apply([("thing", "d", None), ("thing/inner", "f", "x")])
        self.apply([("thing", "f", "now-a-file")])
        self.assertTrue(os.path.isfile(self.p("thing")))

    def test_symlink_replaced_by_regular_file(self):
        self.apply([("bin/target", "f", "t"), ("bin/link", "l", "target")])
        self.apply([("bin/link", "f", "real")])
        self.assertFalse(os.path.islink(self.p("bin/link")))
        with open(self.p("bin/link")) as fh:
            self.assertEqual(fh.read(), "real")

    def test_parent_symlink_replaced_when_dir_needed(self):
        self.apply([("real", "d", None), ("lib", "l", "real")])
        self.apply([("lib/thing", "f", "x")])
        self.assertTrue(os.path.exists(self.p("lib/thing")))

    def test_readonly_dir_mode_does_not_block_later_writes(self):
        stats = dp.ExtractStats()
        dp.extract_layer(make_layer([("ro", "d", None)]), self.root, stats)
        os.chmod(self.p("ro"), 0o555)
        self.apply([("ro/file", "f", "written")])
        self.assertTrue(os.path.exists(self.p("ro/file")))


class _FakeResp(io.BytesIO):
    """Stands in for an HTTPResponse so blob logic can be tested offline."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class TestDigestVerification(unittest.TestCase):
    """A corrupted or tampered layer must never reach the extractor."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dt-digest-")
        self.client = dp.RegistryClient(dp.parse_image("alpine:3.19"))
        self.client._token = "fake-token"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _serve(self, payload: bytes):
        self.client._request = lambda path, accept=None: _FakeResp(payload)

    def test_matching_digest_accepted(self):
        payload = b"real-layer-bytes"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        self._serve(payload)
        dest = os.path.join(self.tmp, "ok.tar")
        self.client.download_blob(digest, dest)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), payload)

    def test_mismatched_digest_rejected(self):
        self._serve(b"tampered-bytes")
        dest = os.path.join(self.tmp, "bad.tar")
        with self.assertRaises(RuntimeError) as ctx:
            self.client.download_blob("sha256:" + "a" * 64, dest)
        self.assertIn("digest mismatch", str(ctx.exception))

    def test_partial_file_removed_on_mismatch(self):
        self._serve(b"tampered-bytes")
        dest = os.path.join(self.tmp, "bad.tar")
        with self.assertRaises(RuntimeError):
            self.client.download_blob("sha256:" + "a" * 64, dest)
        self.assertFalse(os.path.exists(dest), "corrupt blob left on disk")

    def test_no_verify_bypasses_check(self):
        self._serve(b"tampered-bytes")
        dest = os.path.join(self.tmp, "nv.tar")
        self.client.download_blob("sha256:" + "a" * 64, dest, verify=False)
        self.assertTrue(os.path.exists(dest))


class TestPullProgressOutput(TempRoot):
    """The progress lines a user actually sees during a pull.

    A regression once printed a blank line after every already-downloaded
    layer and dumped raw buildkit tabs into the command column. Both are
    asserted here against the real puller with a faked registry.
    """

    def _fake_layer_tar(self) -> bytes:
        return make_layer([("etc/hostname", "f", "host")]).getvalue()

    def _run_pull(self, commands):
        payload = self._fake_layer_tar()
        layers = [
            dp.Layer(
                index=i, digest=f"sha256:{i:064d}", size=len(payload), media_type="", command=c
            )
            for i, c in enumerate(commands)
        ]

        class FakeClient:
            image = dp.parse_image("example/app:latest")

            def download_blob(self, digest, dest, progress=None, verify=True):
                with open(dest, "wb") as fh:
                    fh.write(payload)
                if progress:
                    progress(len(payload))
                return dest

            def close(self):
                pass

        real_client = puller_mod.RegistryClient
        real_resolve = puller_mod.resolve_layers
        puller_mod.RegistryClient = lambda image: FakeClient()
        puller_mod.resolve_layers = lambda client, os_name, arch, strict_tag=False: (layers, {})
        err = io.StringIO()
        real_err = sys.stderr
        sys.stderr = err
        try:
            puller_mod.pull("example/app", str(self.root))
        finally:
            sys.stderr = real_err
            puller_mod.RegistryClient = real_client
            puller_mod.resolve_layers = real_resolve
        return err.getvalue()

    def test_no_blank_lines_between_layers(self):
        # Three layers; only the download-progress line ends with \r, so the
        # extract lines must not be separated by empty ones.
        out = self._run_pull(["RUN a", "RUN b", "RUN c"])
        extract_lines = [ln for ln in out.split("\n") if "] extract" in ln]
        self.assertEqual(len(extract_lines), 3)
        # No completely blank line should appear in the body.
        stripped = out.strip("\n")
        self.assertNotIn("\n\n", stripped, f"blank line in output:\n{out!r}")

    def test_buildkit_tabs_and_newlines_are_collapsed(self):
        out = self._run_pull(["RUN /bin/sh -c set -eux; \t\tapt-get update; \n\tapt-get install"])
        body = "\n".join(ln for ln in out.split("\n") if "] extract" in ln)
        self.assertNotIn("\t", body)
        self.assertIn("apt-get update; apt-get install", body)


class TestPlatformSelection(unittest.TestCase):
    def _index(self, *plats):
        return {
            "manifests": [{"digest": f"sha256:{i}", "platform": p} for i, p in enumerate(plats)]
        }

    def test_exact_match(self):
        idx = self._index(
            {"os": "linux", "architecture": "arm64"},
            {"os": "linux", "architecture": "amd64"},
        )
        self.assertEqual(dp.pick_platform_manifest(idx, "linux", "amd64"), "sha256:1")

    def test_arm64_selectable(self):
        idx = self._index(
            {"os": "linux", "architecture": "amd64"},
            {"os": "linux", "architecture": "arm64"},
        )
        self.assertEqual(dp.pick_platform_manifest(idx, "linux", "arm64"), "sha256:1")

    def test_attestation_entries_ignored(self):
        idx = self._index(
            {"os": "unknown", "architecture": "unknown"},
            {"os": "linux", "architecture": "amd64"},
        )
        self.assertEqual(dp.pick_platform_manifest(idx, "linux", "amd64"), "sha256:1")

    def test_falls_back_to_amd64_then_os_then_first(self):
        idx = self._index({"os": "linux", "architecture": "amd64"})
        self.assertEqual(dp.pick_platform_manifest(idx, "linux", "riscv64"), "sha256:0")
        idx2 = self._index({"os": "linux", "architecture": "ppc64le"})
        self.assertEqual(dp.pick_platform_manifest(idx2, "linux", "riscv64"), "sha256:0")

    def test_empty_index_raises(self):
        with self.assertRaises(RuntimeError):
            dp.pick_platform_manifest({"manifests": []}, "linux", "amd64")


class TestTagSelection(unittest.TestCase):
    """Repos without 'latest' should be diagnosable, not just 'not found'."""

    def test_natural_sort_puts_v9_before_v10(self):
        tags = ["v1", "v10", "v2", "v9", "v27"]
        self.assertEqual(sorted(tags, key=tags_mod.natural_key), ["v1", "v2", "v9", "v10", "v27"])

    def test_newest_tag_prefers_moving_tags(self):
        self.assertEqual(dp.newest_tag(["v1", "v2", "stable"]), "stable")
        self.assertEqual(dp.newest_tag(["v1", "main", "v9"]), "main")

    def test_newest_tag_picks_highest_number(self):
        self.assertEqual(dp.newest_tag(["v1", "v27", "v9"]), "v27")

    def test_newest_tag_of_empty_is_none(self):
        self.assertIsNone(dp.newest_tag([]))

    def test_implicit_latest_is_flagged(self):
        self.assertTrue(dp.parse_image("org/app").ref_implicit)
        self.assertFalse(dp.parse_image("org/app:latest").ref_implicit)
        self.assertFalse(dp.parse_image("org/app:v3").ref_implicit)


class TestMissingLatestMessaging(unittest.TestCase):
    class FakeClient:
        def __init__(self, tags, image):
            self.tags = tags
            self.image = image
            self.asked = []

        def get_manifest(self, ref):
            self.asked.append(ref)
            if ref not in self.tags:
                raise RuntimeError(f"not found: {self.image.repo}:{ref} (/v2/...)")
            return (
                {"layers": [{"digest": "sha256:" + "a" * 64, "size": 1}], "config": {}},
                "application/vnd.oci.image.manifest.v1+json",
            )

        def list_tags(self, limit=100):
            return list(self.tags)

        def get_blob_json(self, digest):
            return {}

    def test_missing_latest_resolves_automatically(self):
        # 'latest' was our default, not the user's request, so failing on it
        # would be failing on our own guess.
        image = dp.parse_image("org/app")
        client = self.FakeClient(["v1", "v9", "v10"], image)
        layers, _ = dp.resolve_layers(client, "linux", "amd64")
        self.assertEqual(len(layers), 1)
        self.assertEqual(image.ref, "v10")  # newest, not first
        self.assertTrue(image.ref_inferred)

    def test_strict_tag_lists_real_tags_instead(self):
        image = dp.parse_image("org/app")
        client = self.FakeClient(["v1", "v9", "v10"], image)
        with self.assertRaises(RuntimeError) as ctx:
            dp.resolve_layers(client, "linux", "amd64", strict_tag=True)
        msg = str(ctx.exception)
        self.assertIn("no 'latest' tag", msg)
        self.assertIn("org/app:v10", msg)

    def test_real_latest_is_never_second_guessed(self):
        image = dp.parse_image("org/app")
        client = self.FakeClient(["latest", "v1"], image)
        dp.resolve_layers(client, "linux", "amd64")
        self.assertEqual(image.ref, "latest")
        self.assertFalse(image.ref_inferred)
        self.assertEqual(client.asked, ["latest"])  # no wasted tag listing

    def test_explicit_tag_missing_does_not_suggest(self):
        # The user named a tag; second-guessing them would hide a real typo.
        image = dp.parse_image("org/app:nope")
        client = self.FakeClient(["v1"], image)
        with self.assertRaises(RuntimeError) as ctx:
            dp.resolve_layers(client, "linux", "amd64")
        self.assertIn("not found", str(ctx.exception))
        self.assertNotIn("no 'latest' tag", str(ctx.exception))
        self.assertFalse(image.ref_inferred)

    def test_repo_with_no_tags_reports_original_error(self):
        image = dp.parse_image("org/app")
        client = self.FakeClient([], image)
        with self.assertRaises(RuntimeError) as ctx:
            dp.resolve_layers(client, "linux", "amd64")
        self.assertIn("not found", str(ctx.exception))


class TestRateLimitHandling(unittest.TestCase):
    """429 is a distinct condition: not our permissions, not a transient blip."""

    def test_rate_limited_is_a_runtime_error(self):
        self.assertTrue(issubclass(dp.RateLimited, RuntimeError))

    def test_batch_stops_instead_of_burning_the_rest(self):
        calls = []

        def fake_pull(image, out_dir, **kw):
            calls.append(image)
            raise dp.RateLimited("rate limited by registry-1.docker.io")

        real, puller_mod.pull = puller_mod.pull, fake_pull
        try:
            results = batch_mod.pull_many(["a", "b", "c"], "/tmp", quiet=True, check_access=False)
        finally:
            puller_mod.pull = real
        # First image discovers the limit; the rest are not attempted.
        self.assertEqual(calls, ["a"])
        self.assertEqual(len(results), 1)
        self.assertIn("rate limited", results[0].error)

    def test_concurrent_batch_skips_remaining_after_limit(self):
        def fake_pull(image, out_dir, **kw):
            raise dp.RateLimited("rate limited")

        real, puller_mod.pull = puller_mod.pull, fake_pull
        try:
            results = batch_mod.pull_many(
                ["a", "b", "c"], "/tmp", quiet=True, concurrency=3, check_access=False
            )
        finally:
            puller_mod.pull = real
        self.assertTrue(all(not r.ok for r in results))
        self.assertTrue(
            any("skipped" in (r.error or "") for r in results[1:])
            or all("rate limited" in (r.error or "") for r in results)
        )

    def test_ordinary_failures_do_not_stop_the_batch(self):
        def fake_pull(image, out_dir, **kw):
            raise RuntimeError("nope")

        real, puller_mod.pull = puller_mod.pull, fake_pull
        try:
            results = batch_mod.pull_many(["a", "b", "c"], "/tmp", quiet=True, check_access=False)
        finally:
            puller_mod.pull = real
        self.assertEqual(len(results), 3)


class TestCredentials(unittest.TestCase):
    """Credentials are env-only, so the tool still runs with nothing installed."""

    def setUp(self):
        self._saved = {
            k: os.environ.get(k)
            for k in (
                "DOCKERHUB_USERNAME",
                "DOCKERHUB_TOKEN",
                "DOCKERHUB_PASSWORD",
                "DOCKER_USERNAME",
                "DOCKER_PASSWORD",
            )
        }
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_no_credentials_by_default(self):
        self.assertIsNone(ratelimit_mod.registry_credentials("dockerhub"))

    def test_username_and_token_are_picked_up(self):
        os.environ["DOCKERHUB_USERNAME"] = "alice"
        os.environ["DOCKERHUB_TOKEN"] = "secret"
        self.assertEqual(ratelimit_mod.registry_credentials("dockerhub"), ("alice", "secret"))

    def test_partial_credentials_are_ignored(self):
        os.environ["DOCKERHUB_USERNAME"] = "alice"
        self.assertIsNone(ratelimit_mod.registry_credentials("dockerhub"))

    def test_docker_prefixed_names_also_work(self):
        os.environ["DOCKER_USERNAME"] = "bob"
        os.environ["DOCKER_PASSWORD"] = "pw"
        self.assertEqual(ratelimit_mod.registry_credentials("dockerhub"), ("bob", "pw"))

    def test_other_registries_are_unaffected(self):
        os.environ["DOCKERHUB_USERNAME"] = "alice"
        os.environ["DOCKERHUB_TOKEN"] = "secret"
        self.assertIsNone(ratelimit_mod.registry_credentials("ecr_public"))


class TestRateBudget(unittest.TestCase):
    """Tell the user the limit is coming before spending the batch on it."""

    def test_parse_rate_header(self):
        self.assertEqual(ratelimit_mod._parse_rate_header("100;w=21600"), (100, 21600))
        self.assertEqual(ratelimit_mod._parse_rate_header("100"), (100, None))
        self.assertEqual(ratelimit_mod._parse_rate_header(None), (None, None))
        self.assertEqual(ratelimit_mod._parse_rate_header("garbage"), (None, None))

    def test_describe_unknown_budget(self):
        self.assertIn("unknown", ratelimit_mod.RateBudget().describe())

    def test_describe_known_budget(self):
        b = ratelimit_mod.RateBudget(limit=100, remaining=7, window_seconds=21600)
        text = b.describe()
        self.assertIn("7/100", text)
        self.assertIn("6h", text)
        self.assertIn("anonymous", text)

    def test_describe_marks_authenticated(self):
        b = ratelimit_mod.RateBudget(
            limit=200, remaining=200, window_seconds=3600, authenticated=True
        )
        self.assertIn("authenticated", b.describe())

    def test_warns_when_list_exceeds_budget(self):
        import contextlib
        import io

        real_check, real_pull = ratelimit_mod.check_rate_budget, puller_mod.pull
        ratelimit_mod.check_rate_budget = lambda timeout=15.0: ratelimit_mod.RateBudget(
            limit=100, remaining=2, window_seconds=21600
        )
        puller_mod.pull = lambda image, out_dir, **kw: "/tmp/x"
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                batch_mod.pull_many(["a", "b", "c", "d"], "/tmp", check_access=False)
        finally:
            ratelimit_mod.check_rate_budget, puller_mod.pull = real_check, real_pull
        text = err.getvalue()
        self.assertIn("only 2 pulls left", text)
        self.assertIn("DOCKERHUB_USERNAME", text)

    def test_no_warning_when_budget_is_ample(self):
        import contextlib
        import io

        real_check, real_pull = ratelimit_mod.check_rate_budget, puller_mod.pull
        ratelimit_mod.check_rate_budget = lambda timeout=15.0: ratelimit_mod.RateBudget(
            limit=100, remaining=100, window_seconds=21600
        )
        puller_mod.pull = lambda image, out_dir, **kw: "/tmp/x"
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                batch_mod.pull_many(["a"], "/tmp", check_access=False)
        finally:
            ratelimit_mod.check_rate_budget, puller_mod.pull = real_check, real_pull
        self.assertNotIn("DOCKERHUB_USERNAME", err.getvalue())

    def test_budget_check_can_be_skipped(self):
        called = []
        real_check, real_pull = ratelimit_mod.check_rate_budget, puller_mod.pull
        ratelimit_mod.check_rate_budget = lambda timeout=15.0: (
            called.append(1) or ratelimit_mod.RateBudget()
        )
        puller_mod.pull = lambda image, out_dir, **kw: "/tmp/x"
        try:
            batch_mod.pull_many(["a"], "/tmp", quiet=True, check_budget=False, check_access=False)
        finally:
            ratelimit_mod.check_rate_budget, puller_mod.pull = real_check, real_pull
        self.assertEqual(called, [])

    def test_stop_message_names_unattempted_images(self):
        import contextlib
        import io
        from unittest import mock

        # The hint only appears when unauthenticated, so do not inherit the
        # developer's real credentials from the environment.
        patcher = mock.patch.dict(os.environ, {}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

        real_check, real_pull = ratelimit_mod.check_rate_budget, puller_mod.pull
        ratelimit_mod.check_rate_budget = lambda timeout=15.0: ratelimit_mod.RateBudget()

        def boom(image, out_dir, **kw):
            raise dp.RateLimited("rate limited")

        puller_mod.pull = boom
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                batch_mod.pull_many(["a", "b", "c"], "/tmp", check_access=False)
        finally:
            ratelimit_mod.check_rate_budget, puller_mod.pull = real_check, real_pull
        text = err.getvalue()
        self.assertIn("2 of 3 images were not attempted", text)
        self.assertIn("DOCKERHUB_TOKEN", text)

    def test_budget_check_failure_never_blocks_the_run(self):
        real_check, real_pull = ratelimit_mod.check_rate_budget, puller_mod.pull

        def explode(timeout=15.0):
            raise OSError("network down")

        ratelimit_mod.check_rate_budget = explode
        puller_mod.pull = lambda image, out_dir, **kw: "/tmp/x"
        try:
            # The pull is stubbed, so there is no folder to verify; this test
            # is about the preflight, not about what landed on disk.
            results = batch_mod.pull_many(
                ["a"], "/tmp", quiet=True, verify_pulls=False, check_access=False
            )
        finally:
            ratelimit_mod.check_rate_budget, puller_mod.pull = real_check, real_pull
        # A broken preflight is not a reason to refuse the actual work.
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)


class TestVerification(unittest.TestCase):
    """Answering "did all of them actually download?" from the filesystem.

    A batch of hundreds scrolls past unread, and the failures that matter
    are silent: an interrupted run, a full disk, a folder that lost files
    in transit. Every assertion here is about catching one of those without
    trusting the log that claimed success.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-verify-test-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _make_image(self, name, files=("bin/sh", "etc/hosts"), complete=True, symlink=None):
        """Build a folder shaped exactly like a finished pull leaves it."""
        dest = os.path.join(self.root, name)
        for rel in files:
            path = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("x" * 10)
        if symlink:
            link = os.path.join(dest, symlink)
            os.makedirs(os.path.dirname(link), exist_ok=True)
            os.symlink("/bin/sh", link)
        os.makedirs(dest, exist_ok=True)
        meta = {
            "image": f"library/{name}:latest",
            "layers": [{"digest": "sha256:abc", "size": 1, "command": "RUN x"}],
            "complete": complete,
            "rootfs": dp.scan_tree(dest).as_dict(),
        }
        with open(os.path.join(dest, ".image.json"), "w") as fh:
            json.dump(meta, fh)
        return dest

    # -- the census ------------------------------------------------------
    def test_scan_counts_files_dirs_and_symlinks(self):
        dest = self._make_image("alpine", symlink="bin/busybox")
        stats = dp.scan_tree(dest)
        self.assertEqual(stats.files, 2)
        self.assertEqual(stats.symlinks, 1)
        self.assertEqual(stats.dirs, 2)  # bin/ and etc/
        self.assertEqual(stats.bytes, 20)

    def test_scan_does_not_follow_symlinks_out_of_the_tree(self):
        """A symlink to / must count as one entry, not as the whole disk."""
        dest = os.path.join(self.root, "escape")
        os.makedirs(dest)
        os.symlink("/", os.path.join(dest, "everything"))
        stats = dp.scan_tree(dest)
        self.assertEqual((stats.symlinks, stats.files, stats.dirs), (1, 0, 0))

    def test_scan_excludes_our_own_bookkeeping(self):
        """.image.json and .layers/ are ours, not the image's filesystem."""
        dest = self._make_image("redis")
        os.makedirs(os.path.join(dest, ".layers"))
        with open(os.path.join(dest, ".layers", "000.tar"), "w") as fh:
            fh.write("tarball")
        stats = dp.scan_tree(dest)
        self.assertEqual(stats.files, 2, "layer cache or metadata leaked into the count")

    # -- one image -------------------------------------------------------
    def test_complete_image_verifies(self):
        dest = self._make_image("alpine")
        self.assertTrue(dp.verify_dest(dest).ok)

    def test_missing_folder_is_reported_missing(self):
        res = dp.verify_dest(os.path.join(self.root, "never-pulled"))
        self.assertEqual(res.status, "missing")
        self.assertFalse(res.ok)

    def test_folder_without_a_record_is_incomplete(self):
        """An interrupted pull leaves files but never writes the marker."""
        dest = os.path.join(self.root, "half")
        os.makedirs(os.path.join(dest, "bin"))
        with open(os.path.join(dest, "bin", "sh"), "w") as fh:
            fh.write("x")
        res = dp.verify_dest(dest)
        self.assertEqual(res.status, "incomplete")

    def test_record_not_marked_complete_is_incomplete(self):
        dest = self._make_image("partial", complete=False)
        self.assertEqual(dp.verify_dest(dest).status, "incomplete")

    def test_corrupt_record_is_incomplete_not_a_crash(self):
        dest = self._make_image("alpine")
        with open(os.path.join(dest, ".image.json"), "w") as fh:
            fh.write("{not json")
        self.assertEqual(dp.verify_dest(dest).status, "incomplete")

    def test_deleted_file_after_the_pull_is_caught(self):
        """The case a completion marker alone cannot catch."""
        dest = self._make_image("alpine")
        os.remove(os.path.join(dest, "etc", "hosts"))
        res = dp.verify_dest(dest)
        self.assertEqual(res.status, "mismatch")
        self.assertTrue(any("file count" in p for p in res.problems))

    def test_truncated_file_is_caught_by_byte_count(self):
        """Same file count, less content: a partial copy."""
        dest = self._make_image("alpine")
        with open(os.path.join(dest, "etc", "hosts"), "w") as fh:
            fh.write("x")
        res = dp.verify_dest(dest)
        self.assertEqual(res.status, "mismatch")
        self.assertTrue(any("byte count" in p for p in res.problems))

    def test_quick_check_skips_the_tree_walk(self):
        """Quick answers "did the pull finish?", not "is every byte here?"."""
        dest = self._make_image("alpine")
        os.remove(os.path.join(dest, "etc", "hosts"))
        self.assertTrue(dp.verify_dest(dest, quick=True).ok)
        self.assertFalse(dp.verify_dest(dest, quick=False).ok)

    def test_record_without_a_census_still_verifies(self):
        """Folders pulled by an older version must not be called broken."""
        dest = self._make_image("legacy")
        with open(os.path.join(dest, ".image.json")) as fh:
            meta = json.load(fh)
        del meta["rootfs"]
        with open(os.path.join(dest, ".image.json"), "w") as fh:
            json.dump(meta, fh)
        res = dp.verify_dest(dest)
        self.assertTrue(res.ok)
        self.assertTrue(any("predates" in p for p in res.problems))

    # -- many images -----------------------------------------------------
    def test_list_reports_an_image_that_never_downloaded(self):
        """The whole point: start from what was asked for, not what exists."""
        self._make_image("library_alpine_3.19")
        results = dp.verify_list(["alpine:3.19", "redis:7"], self.root)
        by_image = {r.image: r for r in results}
        self.assertTrue(by_image["alpine:3.19"].ok)
        self.assertEqual(by_image["redis:7"].status, "missing")

    def test_list_survives_an_unparseable_reference(self):
        results = dp.verify_list(["not a/valid/ref/at/all"], self.root)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].ok)

    def test_output_dir_scan_finds_every_folder(self):
        self._make_image("one")
        self._make_image("two")
        results = dp.verify_output_dir(self.root)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.ok for r in results))

    def test_output_dir_accepts_a_single_extracted_image(self):
        """Pointing at one rootfs should check it, not look for children."""
        dest = self._make_image("solo")
        results = dp.verify_output_dir(dest)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)

    def test_output_dir_ignores_stray_dot_directories(self):
        """A --keep-tar run can leave `.layers/` behind; it is not an image."""
        self._make_image("real")
        os.makedirs(os.path.join(self.root, ".layers"))
        results = dp.verify_output_dir(self.root)
        self.assertEqual([r.image for r in results], ["library/real:latest"])

    # -- saying what was checked ------------------------------------------
    def test_a_passing_check_still_records_what_it_looked_at(self):
        """Silence on success is why 'verified' feels like a word, not a fact."""
        dest = self._make_image("alpine")
        res = dp.verify_dest(dest)
        self.assertTrue(res.ok)
        self.assertTrue(res.checks, "a passing verification recorded nothing")
        self.assertTrue(all(c.passed for c in res.checks))

    def test_deep_names_every_count_it_compared(self):
        dest = self._make_image("alpine")
        names = [c.name for c in dp.verify_dest(dest, quick=False).checks]
        for expected in ("file count", "dir count", "symlink count", "byte count"):
            self.assertIn(expected, names)

    def test_quick_does_not_claim_counts_it_never_compared(self):
        """The report must not imply work that was skipped."""
        dest = self._make_image("alpine")
        names = [c.name for c in dp.verify_dest(dest, quick=True).checks]
        self.assertNotIn("file count", names)
        self.assertIn("pull completed", names)

    def test_summary_counts_the_checks_and_names_the_depth(self):
        dest = self._make_image("alpine")
        quick = dp.verify_dest(dest, quick=True)
        deep = dp.verify_dest(dest, quick=False)
        self.assertIn("quick", quick.summary())
        self.assertIn("deep", deep.summary())
        # Deep does strictly more work, and must say so.
        self.assertGreater(len(deep.checks), len(quick.checks))

    def test_explain_shows_the_evidence_not_just_a_verdict(self):
        """Each line must carry the number it compared, not the word 'ok'.

        The prose description of each check lives in CHECK_HELP and is
        printed once as a legend, so the per-line space goes to evidence.
        """
        dest = self._make_image("alpine")
        lines = dp.verify_dest(dest).explain()
        self.assertTrue(lines)
        joined = "\n".join(lines)
        self.assertIn("file count", joined)
        self.assertIn("2 == 2", joined)
        # No line may wrap in a terminal, which is what made this unreadable.
        for line in lines:
            self.assertLess(len(line), 80, f"line too long to read: {line!r}")

    def test_a_failing_line_names_both_numbers(self):
        dest = self._make_image("alpine")
        os.remove(os.path.join(dest, "etc", "hosts"))
        lines = dp.verify_dest(dest).explain()
        failing = [ln for ln in lines if ln.startswith("FAIL")]
        self.assertTrue(failing)
        self.assertIn("recorded 2, found 1", "\n".join(failing))

    def test_a_failing_check_is_recorded_as_failed_not_omitted(self):
        dest = self._make_image("alpine")
        os.remove(os.path.join(dest, "etc", "hosts"))
        res = dp.verify_dest(dest)
        failed = [c for c in res.checks if not c.passed]
        self.assertTrue(failed)
        self.assertIn("file count", [c.name for c in failed])

    def test_every_check_name_has_an_explanation(self):
        """A new check must not ship without saying what it inspects."""
        dest = self._make_image("alpine")
        for res in (dp.verify_dest(dest, quick=True), dp.verify_dest(dest, quick=False)):
            for check in res.checks:
                self.assertIn(check.name, dp.CHECK_HELP, f"{check.name} has no explanation")

    def test_report_dict_carries_the_checks(self):
        dest = self._make_image("alpine")
        d = dp.verify_dest(dest).as_dict()
        self.assertEqual(d["depth"], "deep")
        self.assertTrue(d["checks"])
        self.assertIn("check", d["checks"][0])

    def test_result_serialises_for_a_report(self):
        dest = self._make_image("alpine")
        d = dp.verify_dest(dest).as_dict()
        self.assertTrue(d["ok"])
        self.assertEqual(d["status"], "ok")
        self.assertIn("dest", d)


class TestPullWritesAVerifiableRecord(unittest.TestCase):
    """The pull must leave behind something later runs can actually check."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-record-test-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _fake_pull(self, quiet=True):
        """Run the real puller against a faked registry of two tiny layers."""
        layers = []
        blobs = {}
        for i, (name, body) in enumerate([("bin/sh", b"shell"), ("etc/hosts", b"hosts")]):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tf:
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tf.addfile(info, io.BytesIO(body))
            raw = buf.getvalue()
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            blobs[digest] = raw
            layers.append(
                dp.Layer(
                    index=i,
                    digest=digest,
                    size=len(raw),
                    media_type="application/vnd.oci.image.layer.v1.tar",
                    command=f"RUN step{i}",
                )
            )

        class FakeClient:
            def __init__(self):
                self.image = dp.parse_image("example/app:1.0")

            def download_blob(self, digest, dest, progress=None, verify=True):
                with open(dest, "wb") as fh:
                    fh.write(blobs[digest])
                return dest

            def close(self):
                pass

        real_client, real_resolve = puller_mod.RegistryClient, puller_mod.resolve_layers
        puller_mod.RegistryClient = lambda image: FakeClient()
        puller_mod.resolve_layers = lambda c, o, a, strict_tag=False: (layers, {"config": {}})
        try:
            return puller_mod.pull("example/app:1.0", self.root, quiet=quiet)
        finally:
            puller_mod.RegistryClient = real_client
            puller_mod.resolve_layers = real_resolve

    def test_a_real_pull_verifies_immediately_afterwards(self):
        """End to end: pull, then prove it landed, with no network."""
        dest = self._fake_pull()
        res = dp.verify_dest(dest)
        self.assertTrue(res.ok, res.problems)
        self.assertEqual(res.expected, res.found)

    def test_record_is_marked_complete_and_counts_the_tree(self):
        dest = self._fake_pull()
        with open(os.path.join(dest, ".image.json")) as fh:
            meta = json.load(fh)
        self.assertTrue(meta["complete"])
        self.assertEqual(meta["rootfs"]["files"], 2)
        self.assertEqual(meta["layer_count"], 2)

    def test_damage_after_a_real_pull_is_detected(self):
        dest = self._fake_pull()
        os.remove(os.path.join(dest, "bin", "sh"))
        self.assertFalse(dp.verify_dest(dest).ok)

    def test_no_temp_record_is_left_behind(self):
        """The atomic write must not litter a .tmp next to the real file."""
        dest = self._fake_pull()
        self.assertFalse(os.path.exists(os.path.join(dest, ".image.json.tmp")))


class TestBatchVerifiesWhatItPulled(unittest.TestCase):
    """A batch must report on disk reality, not on what pull() returned."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-batch-verify-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self._real_pull = puller_mod.pull

    def tearDown(self):
        puller_mod.pull = self._real_pull

    def _stub(self, land: set):
        """Stub a pull that only really creates folders for `land`."""

        def fake(image, out_dir, **kw):
            dest = os.path.join(out_dir, image.replace("/", "_"))
            if image in land:
                os.makedirs(dest, exist_ok=True)
                with open(os.path.join(dest, "file"), "w") as fh:
                    fh.write("data")
                meta = {
                    "image": image,
                    "layers": [{"digest": "sha256:a", "size": 1}],
                    "complete": True,
                    "rootfs": dp.scan_tree(dest).as_dict(),
                }
                with open(os.path.join(dest, ".image.json"), "w") as fh:
                    json.dump(meta, fh)
            return dest

        puller_mod.pull = fake

    def test_a_pull_that_lied_about_success_is_marked_failed(self):
        """The failure mode verification exists for: success with no folder."""
        self._stub(land={"a"})
        results = batch_mod.pull_many(
            ["a", "b"], self.root, quiet=True, check_budget=False, check_access=False
        )
        by_image = {r.image: r for r in results}
        self.assertTrue(by_image["a"].ok)
        self.assertFalse(by_image["b"].ok, "a missing folder was reported as success")
        self.assertEqual(by_image["b"].verify_status, "missing")

    def test_verified_tally_is_printed(self):
        self._stub(land={"a", "b"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            batch_mod.pull_many(["a", "b"], self.root, check_budget=False, check_access=False)
        self.assertIn("2/2 verified on disk", err.getvalue())

    def test_verification_can_be_turned_off(self):
        self._stub(land=set())
        results = batch_mod.pull_many(
            ["a"],
            self.root,
            quiet=True,
            check_budget=False,
            verify_pulls=False,
            check_access=False,
        )
        self.assertTrue(results[0].ok)
        self.assertIsNone(results[0].verified)

    def test_batch_states_its_verification_method_up_front(self):
        """'ok' means nothing unless the reader knows what was checked."""
        self._stub(land={"a"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            batch_mod.pull_many(["a"], self.root, check_budget=False, check_access=False)
        text = err.getvalue()
        self.assertIn("verifying each image (quick)", text)
        self.assertIn("pull marked complete", text)

    def test_deep_batch_says_it_is_deep_and_what_that_means(self):
        self._stub(land={"a"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            batch_mod.pull_many(
                ["a"], self.root, check_budget=False, deep_verify=True, check_access=False
            )
        text = err.getvalue()
        self.assertIn("verifying each image (deep)", text)
        self.assertIn("re-walked", text)

    def test_each_ok_line_carries_the_evidence_behind_it(self):
        self._stub(land={"a"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            batch_mod.pull_many(["a"], self.root, check_budget=False, check_access=False)
        self.assertIn("checks passed", err.getvalue())

    def test_report_dict_carries_the_verification_outcome(self):
        self._stub(land=set())
        results = batch_mod.pull_many(
            ["a"], self.root, quiet=True, check_budget=False, check_access=False
        )
        d = results[0].as_dict()
        self.assertFalse(d["ok"])
        self.assertFalse(d["verified"])
        self.assertIn("verify_problems", d)

    def test_report_names_the_individual_checks_for_a_good_pull(self):
        """A machine-readable run must also be able to show its working."""
        self._stub(land={"a"})
        results = batch_mod.pull_many(
            ["a"], self.root, quiet=True, check_budget=False, check_access=False
        )
        d = results[0].as_dict()
        self.assertTrue(d["verified"])
        self.assertIn("verify_summary", d)
        self.assertTrue(d["verify_checks"])
        self.assertIn("check", d["verify_checks"][0])

    def test_deep_verification_catches_post_pull_damage(self):
        """Quick trusts the marker; deep re-counts, so it sees partial loss.

        The folder still has files, so nothing about it looks wrong until
        the counts are compared. This is the case that needs --deep.
        """

        def fake(image, out_dir, **kw):
            dest = os.path.join(out_dir, image)
            os.makedirs(dest, exist_ok=True)
            for name in ("keep", "lose"):
                with open(os.path.join(dest, name), "w") as fh:
                    fh.write("data")
            meta = {
                "image": image,
                "layers": [{"digest": "sha256:a", "size": 1}],
                "complete": True,
                "rootfs": dp.scan_tree(dest).as_dict(),
            }
            with open(os.path.join(dest, ".image.json"), "w") as fh:
                json.dump(meta, fh)
            # Something eats one file between extraction and the check.
            os.remove(os.path.join(dest, "lose"))
            return dest

        puller_mod.pull = fake
        quick = batch_mod.pull_many(
            ["a"], self.root, quiet=True, check_budget=False, check_access=False
        )
        self.assertTrue(quick[0].ok, "quick should not walk the tree")
        deep = batch_mod.pull_many(
            ["a"],
            self.root,
            quiet=True,
            check_budget=False,
            deep_verify=True,
            check_access=False,
        )
        self.assertFalse(deep[0].ok)

    def test_quick_still_rejects_a_folder_emptied_entirely(self):
        """Quick is cheap, but it must not bless a folder with nothing in it."""

        def fake(image, out_dir, **kw):
            dest = os.path.join(out_dir, image)
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "file"), "w") as fh:
                fh.write("data")
            meta = {
                "image": image,
                "layers": [{"digest": "sha256:a", "size": 1}],
                "complete": True,
                "rootfs": dp.scan_tree(dest).as_dict(),
            }
            with open(os.path.join(dest, ".image.json"), "w") as fh:
                json.dump(meta, fh)
            os.remove(os.path.join(dest, "file"))
            return dest

        puller_mod.pull = fake
        results = batch_mod.pull_many(
            ["a"], self.root, quiet=True, check_budget=False, check_access=False
        )
        self.assertFalse(results[0].ok)


class TestPreflightClassification(unittest.TestCase):
    """Deciding pullable from not, before spending a download on finding out.

    The registry hands a token to anyone and only refuses at the manifest,
    so the two signals have to be read in the right order. These fake the
    network: the live behaviour they encode was measured against Docker
    Hub first, and is asserted here so it cannot drift silently.
    """

    def setUp(self):
        self._real_client = preflight_mod.RegistryClient
        self._real_head = preflight_mod._head_manifest

    def tearDown(self):
        preflight_mod.RegistryClient = self._real_client
        preflight_mod._head_manifest = self._real_head

    def _fake(self, has_access=True, head_status=200, tags=None, token="tok"):
        """Stand in for the registry with a specific, named behaviour."""

        class FakeClient:
            def __init__(self, image, timeout=30.0):
                self.image = image

            @property
            def token(self):
                return token

            def _token_has_access(self):
                return has_access

            def list_tags(self, limit=100):
                return list(tags or [])

            def close(self):
                pass

        preflight_mod.RegistryClient = FakeClient
        preflight_mod._head_manifest = lambda c, repo, ref, timeout: head_status

    # -- the cases the user actually has ---------------------------------
    def test_a_public_image_is_pullable(self):
        self._fake(has_access=True, head_status=200)
        res = preflight_mod.check_access("alpine:3.19")
        self.assertTrue(res.ok)
        self.assertEqual(res.status, "ok")

    def test_no_token_scope_means_private_or_taken_down(self):
        """The cheap signal: the token itself says the repo is not readable."""
        self._fake(has_access=False)
        res = preflight_mod.check_access("someone/private-thing")
        self.assertEqual(res.status, "inaccessible")
        self.assertIn("private, deleted, or taken down", res.detail)

    def test_manifest_401_also_means_inaccessible(self):
        """Belt and braces: a token can look fine and still be refused."""
        self._fake(has_access=True, head_status=401)
        self.assertEqual(preflight_mod.check_access("org/app").status, "inaccessible")

    def test_an_explicit_tag_that_does_not_exist_is_its_own_case(self):
        """A live repo with a wrong tag is a typo, not a takedown."""
        self._fake(has_access=True, head_status=404, tags=["1.0", "2.0"])
        res = preflight_mod.check_access("org/app:nope")
        self.assertEqual(res.status, "missing_tag")
        self.assertIn("no tag 'nope'", res.detail)
        self.assertEqual(res.available_tags, ["1.0", "2.0"])

    def test_missing_latest_is_not_a_failure_when_we_invented_it(self):
        """The puller falls back to the newest tag, so this must agree.

        Rejecting these would make the preflight refuse images that
        download perfectly well, which is worse than not checking at all.
        """
        self._fake(has_access=True, head_status=404, tags=["0.1", "0.2"])
        res = preflight_mod.check_access("org/app")  # no tag typed
        self.assertTrue(res.ok, "an implicit ':latest' must not be rejected")

    def test_a_repo_with_no_tags_at_all_is_reported(self):
        self._fake(has_access=True, head_status=404, tags=[])
        res = preflight_mod.check_access("org/empty")
        self.assertEqual(res.status, "missing_tag")
        self.assertIn("no tags at all", res.detail)

    def test_rate_limit_is_distinct_from_inaccessible(self):
        """Being throttled says nothing about whether the image exists."""
        self._fake(has_access=True, head_status=429)
        self.assertEqual(preflight_mod.check_access("org/app").status, "rate_limited")

    def test_an_unparseable_reference_is_an_error_not_a_crash(self):
        res = preflight_mod.check_access("not a/valid/ref/at/all")
        self.assertEqual(res.status, "error")
        self.assertFalse(res.ok)

    def test_a_network_failure_is_recorded_not_raised(self):
        """A preflight that throws would be worse than no preflight."""

        class Boom:
            def __init__(self, image, timeout=30.0):
                self.image = image

            @property
            def token(self):
                raise OSError("network down")

            def close(self):
                pass

        preflight_mod.RegistryClient = Boom
        res = preflight_mod.check_access("alpine")
        self.assertEqual(res.status, "error")
        self.assertIn("network down", res.detail)

    # -- the list-level answer -------------------------------------------
    def test_check_many_preserves_input_order(self):
        """The output is read against the user's list, so order matters."""
        self._fake(has_access=True, head_status=200)
        refs = [f"org/app{i}" for i in range(12)]
        got = [r.image for r in preflight_mod.check_many(refs, concurrency=4)]
        self.assertEqual(got, refs)

    def test_summarize_counts_every_status(self):
        results = [
            preflight_mod.AccessResult("a"),
            preflight_mod.AccessResult("b", status="inaccessible"),
            preflight_mod.AccessResult("c", status="inaccessible"),
            preflight_mod.AccessResult("d", status="missing_tag"),
        ]
        counts = preflight_mod.summarize(results)
        self.assertEqual(counts["total"], 4)
        self.assertEqual(counts["ok"], 1)
        self.assertEqual(counts["inaccessible"], 2)
        self.assertEqual(counts["unavailable"], 3)
        # Keys a reporter needs must exist even at zero.
        self.assertEqual(counts["rate_limited"], 0)

    def test_empty_list_is_not_an_error(self):
        self.assertEqual(preflight_mod.check_many([]), [])

    def test_an_inaccessible_repo_costs_only_the_token_request(self):
        """The cheap signal must short-circuit, not fall through to a HEAD.

        On a list where many repos are gone, doing the manifest request
        anyway would double the connections for no new information.
        """
        heads = []
        self._fake(has_access=False)
        real_head = preflight_mod._head_manifest
        preflight_mod._head_manifest = lambda *a: heads.append(1) or 404
        try:
            preflight_mod.check_access("org/gone")
        finally:
            preflight_mod._head_manifest = real_head
        self.assertEqual(heads, [], "made a manifest request for an unreadable repo")

    def test_a_present_tag_does_not_pay_for_a_tag_listing(self):
        """Listing tags is for explaining failures, not confirming success."""
        listed = []
        self._fake(has_access=True, head_status=200)
        base = preflight_mod.RegistryClient

        class Counting(base):
            def list_tags(self, limit=100):
                listed.append(1)
                return []

        preflight_mod.RegistryClient = Counting
        res = preflight_mod.check_access("org/app:1.0")
        self.assertTrue(res.ok)
        self.assertEqual(listed, [], "listed tags despite the manifest existing")

    def test_result_serialises_for_a_report(self):
        res = preflight_mod.AccessResult(
            "org/app", status="missing_tag", detail="no tag", available_tags=["1"]
        )
        d = res.as_dict()
        self.assertFalse(d["ok"])
        self.assertEqual(d["status"], "missing_tag")
        self.assertEqual(d["available_tags"], ["1"])


class TestBatchSkipsUnreachableImages(unittest.TestCase):
    """The batch must not spend a download discovering a repo is gone."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dt-skip-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self._real_pull = puller_mod.pull
        self._real_check = batch_mod.preflight.check_many
        self.attempted = []

    def tearDown(self):
        puller_mod.pull = self._real_pull
        batch_mod.preflight.check_many = self._real_check

    def _setup(self, reachable: set, names: list):
        def fake_check(images, concurrency=8, timeout=30.0, on_result=None):
            return [
                preflight_mod.AccessResult(i)
                if i in reachable
                else preflight_mod.AccessResult(
                    i, status="inaccessible", detail=f"{i} is private, deleted, or taken down"
                )
                for i in images
            ]

        def fake_pull(image, out_dir, **kw):
            self.attempted.append(image)
            dest = os.path.join(out_dir, image.replace("/", "_"))
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "f"), "w") as fh:
                fh.write("x")
            meta = {
                "image": image,
                "layers": [{"digest": "sha256:a"}],
                "complete": True,
                "rootfs": dp.scan_tree(dest).as_dict(),
            }
            with open(os.path.join(dest, ".image.json"), "w") as fh:
                json.dump(meta, fh)
            return dest

        batch_mod.preflight.check_many = fake_check
        puller_mod.pull = fake_pull
        return names

    def test_unreachable_images_are_never_downloaded(self):
        """The whole point: do not spend a pull on a repo that is gone."""
        names = self._setup({"good1", "good2"}, ["good1", "gone1", "good2", "gone2"])
        batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        self.assertEqual(sorted(self.attempted), ["good1", "good2"])

    def test_every_image_from_the_list_is_still_accounted_for(self):
        """A shorter answer than the question asked would be a lie."""
        names = self._setup({"good1"}, ["good1", "gone1", "gone2"])
        results = batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        self.assertEqual(len(results), 3)
        self.assertEqual({r.image for r in results}, set(names))

    def test_skipped_is_distinct_from_failed(self):
        """'Never downloadable' and 'download broke' need different fixes."""
        names = self._setup({"good1"}, ["good1", "gone1"])
        results = batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        by = {r.image: r for r in results}
        self.assertFalse(by["gone1"].skipped is False)
        self.assertTrue(by["gone1"].skipped)
        self.assertFalse(by["good1"].skipped)
        self.assertEqual(by["gone1"].access_status, "inaccessible")

    def test_the_count_is_reported(self):
        names = self._setup({"a"}, ["a", "b", "c"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            batch_mod.pull_many(names, self.root, check_budget=False)
        text = err.getvalue()
        self.assertIn("1/3 accessible, 2 not", text)
        self.assertIn("2 of 3 images were never downloadable", text)

    def test_the_names_are_written_to_a_file(self):
        """A count alone is not actionable; the list is."""
        names = self._setup({"a"}, ["a", "b", "c"])
        batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        path = os.path.join(self.root, "not-downloaded.txt")
        self.assertTrue(os.path.exists(path), "no skip list written")
        body = open(path).read()
        self.assertIn("b", body)
        self.assertIn("c", body)
        self.assertIn("private, deleted, or taken down", body)

    def test_the_skip_file_feeds_straight_back_into_the_tool(self):
        """Re-running when the repos come back must not need hand editing."""
        names = self._setup({"a"}, ["a", "b", "c"])
        batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        path = os.path.join(self.root, "not-downloaded.txt")
        self.assertEqual(batch_mod.read_image_list(path), ["b", "c"])

    def test_everything_unreachable_stops_before_downloading(self):
        names = self._setup(set(), ["x", "y"])
        results = batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        self.assertEqual(self.attempted, [])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.skipped for r in results))
        self.assertTrue(os.path.exists(os.path.join(self.root, "not-downloaded.txt")))

    def test_the_preflight_can_be_turned_off(self):
        """Opting out must really skip the check, not just ignore it."""
        called = []
        names = self._setup({"a"}, ["a", "b"])
        real = batch_mod.preflight.check_many
        batch_mod.preflight.check_many = lambda *a, **k: called.append(1) or real(*a, **k)
        try:
            batch_mod.pull_many(
                names, self.root, quiet=True, check_budget=False, check_access=False
            )
        finally:
            batch_mod.preflight.check_many = real
        self.assertEqual(called, [], "preflight ran despite check_access=False")
        self.assertEqual(sorted(self.attempted), ["a", "b"])

    def test_a_single_image_is_not_worth_a_preflight_pass(self):
        """One image discovers the problem just as fast by trying."""
        called = []
        batch_mod.preflight.check_many = lambda *a, **k: called.append(1) or []
        puller_mod.pull = lambda image, out_dir, **kw: "/tmp/x"
        batch_mod.pull_many(["solo"], self.root, quiet=True, check_budget=False, verify_pulls=False)
        self.assertEqual(called, [])

    def test_report_dict_marks_the_skip(self):
        names = self._setup({"a"}, ["a", "b"])
        results = batch_mod.pull_many(names, self.root, quiet=True, check_budget=False)
        d = {r.image: r.as_dict() for r in results}
        self.assertTrue(d["b"]["skipped"])
        self.assertEqual(d["b"]["access_status"], "inaccessible")
        self.assertNotIn("skipped", d["a"])

    def test_the_skip_file_keeps_the_reference_the_user_wrote(self):
        """Real lists are hub.docker.com URLs, and the retry file must match.

        Rewriting them to 'namespace/repo' would still work as input, but it
        would no longer line up with the user's own list, which is the thing
        the file is meant to be compared against.
        """
        urls = [
            "https://hub.docker.com/r/someone/gone",
            "https://hub.docker.com/r/someone/alive",
        ]
        self._setup({urls[1]}, urls)
        batch_mod.pull_many(urls, self.root, quiet=True, check_budget=False)
        body = open(os.path.join(self.root, "not-downloaded.txt")).read()
        self.assertIn("https://hub.docker.com/r/someone/gone", body)
        self.assertNotIn("https://hub.docker.com/r/someone/alive", body)


class TestPathFilter(TempRoot):
    """Extracting part of an image must keep exactly that part.

    The risk of a filter is silent loss: files vanish and nothing says so.
    These pin the boundaries where that would happen.
    """

    def filtered(self, entries, paths) -> tuple[dp.ExtractStats, int]:
        stats = dp.ExtractStats()
        pf = dp.PathFilter(paths)
        added = dp.extract_layer(make_layer(entries), self.root, stats, path_filter=pf)
        return stats, added

    def test_only_the_wanted_subtree_is_written(self):
        entries = [
            ("app", "d", None),
            ("app/main.py", "f", "print(1)"),
            ("usr", "d", None),
            ("usr/bin/ls", "f", "binary"),
            ("etc/passwd", "f", "root:x:0:0"),
        ]
        stats, _ = self.filtered(entries, ["/app"])
        self.assertTrue(os.path.exists(self.p("app/main.py")))
        self.assertFalse(os.path.exists(self.p("usr/bin/ls")))
        self.assertFalse(os.path.exists(self.p("etc/passwd")))
        self.assertTrue(stats.filtered > 0)

    def test_leading_slash_and_bare_name_mean_the_same_path(self):
        entries = [("app/main.py", "f", "x")]
        for spec in ("/app", "app", "/app/"):
            shutil.rmtree(self.root, ignore_errors=True)
            os.makedirs(self.root, exist_ok=True)
            self.filtered(entries, [spec])
            self.assertTrue(os.path.exists(self.p("app/main.py")), f"{spec} did not match")

    def test_a_sibling_with_a_shared_prefix_is_not_swept_in(self):
        """/app must not drag in /application, which merely starts the same."""
        entries = [
            ("app/main.py", "f", "keep"),
            ("application/other.py", "f", "drop"),
        ]
        self.filtered(entries, ["/app"])
        self.assertTrue(os.path.exists(self.p("app/main.py")))
        self.assertFalse(os.path.exists(self.p("application/other.py")))

    def test_a_whiteout_inside_the_filter_still_deletes(self):
        """Overlay deletes must survive filtering, or stale files come back."""
        self.filtered([("app/old.py", "f", "gone")], ["/app"])
        self.assertTrue(os.path.exists(self.p("app/old.py")))
        self.filtered([("app/.wh.old.py", "f", "")], ["/app"])
        self.assertFalse(os.path.exists(self.p("app/old.py")))

    def test_a_whiteout_outside_the_filter_is_ignored(self):
        """A delete aimed elsewhere must not be counted as work we did."""
        stats, _ = self.filtered([("usr/.wh.thing", "f", "")], ["/app"])
        self.assertEqual(stats.whiteouts, 0)
        self.assertTrue(stats.filtered > 0)

    def test_symlinks_inside_the_filter_survive(self):
        entries = [("app/real.py", "f", "x"), ("app/link.py", "l", "real.py")]
        self.filtered(entries, ["/app"])
        self.assertTrue(os.path.islink(self.p("app/link.py")))

    def test_a_hardlink_to_a_filtered_out_target_is_reported_not_hidden(self):
        """The one way filtering can lose data, so it must be counted."""
        entries = [
            ("usr/share/data", "f", "payload"),
            ("app/data", "h", "usr/share/data"),
        ]
        stats, _ = self.filtered(entries, ["/app"])
        self.assertEqual(stats.unresolved_links, 1)
        self.assertIn("filtered-out targets", str(stats))

    def test_contribution_count_reports_layers_that_held_files(self):
        _, added = self.filtered([("app/a.py", "f", "x"), ("etc/b", "f", "y")], ["/app"])
        self.assertEqual(added, 1)
        _, none = self.filtered([("etc/c", "f", "z")], ["/app"])
        self.assertEqual(none, 0)

    def test_no_filter_extracts_everything(self):
        """The default path must be untouched by the feature."""
        stats = self.apply([("etc/passwd", "f", "root"), ("app/main.py", "f", "x")])
        self.assertTrue(os.path.exists(self.p("etc/passwd")))
        self.assertTrue(os.path.exists(self.p("app/main.py")))
        self.assertEqual(stats.filtered, 0)


class TestCoverageReport(unittest.TestCase):
    """The report is the answer to "did I miss anything?", so it must be honest."""

    def test_copy_and_add_destinations_are_recovered(self):
        cmds = [
            "ADD alpine-minirootfs.tar.gz / # buildkit",
            "RUN /bin/sh -c apk add curl",
            "COPY docker-entrypoint.sh /usr/local/bin/ # buildkit",
            "COPY --from=builder /build/dist /app # buildkit",
        ]
        found = coverage_mod.copy_destinations(cmds)
        self.assertEqual([d.path for d in found], ["/", "/usr/local/bin/", "/app"])
        # --from=builder must not be mistaken for the destination.
        self.assertEqual(found[-1].verb, "COPY")

    def test_a_destination_outside_the_filter_is_flagged(self):
        cmds = ["COPY . /app # buildkit", "COPY run.sh /run.sh # buildkit"]
        report = coverage_mod.build_report(("app",), cmds, {"app": 5}, {0: 5})
        self.assertFalse(report.clean)
        self.assertEqual([d.path for d in report.uncovered], ["/run.sh"])

    def test_everything_inside_the_filter_reports_clean(self):
        cmds = ["COPY . /app # buildkit", "COPY x /app/sub # buildkit"]
        report = coverage_mod.build_report(("app",), cmds, {"app": 9}, {0: 9})
        self.assertTrue(report.clean)
        self.assertEqual(report.uncovered, [])

    def test_a_path_that_matched_nothing_is_called_out(self):
        """A typo must not look like an image that simply has no app."""
        report = coverage_mod.build_report(("typo",), [], {"typo": 0}, {})
        self.assertEqual(report.empty_paths, ["typo"])
        self.assertFalse(report.clean)
        self.assertTrue(any("matched nothing" in line for line in report.lines()))

    def test_unresolved_links_make_the_report_unclean(self):
        report = coverage_mod.build_report(("app",), [], {"app": 3}, {0: 3}, unresolved_links=2)
        self.assertFalse(report.clean)
        self.assertTrue(any("hardlink" in line for line in report.lines()))

    def test_working_dir_treats_root_as_unset(self):
        """Filtering on '/' would keep everything, so it cannot count as an app dir."""
        self.assertEqual(coverage_mod.working_dir({"config": {"WorkingDir": "/app"}}), "/app")
        self.assertEqual(coverage_mod.working_dir({"config": {"WorkingDir": "/"}}), "")
        self.assertEqual(coverage_mod.working_dir({"config": {}}), "")
        self.assertEqual(coverage_mod.working_dir({}), "")

    def test_a_copy_into_a_parent_of_the_filter_still_counts_as_covered(self):
        """`COPY . /` does deliver /app/main.py when the filter is /app."""
        report = coverage_mod.build_report(("app",), ["COPY . / # buildkit"], {"app": 2}, {0: 2})
        self.assertTrue(report.clean)


class TestStepFormatting(unittest.TestCase):
    """The layer list is read by eye, so the noise has to go.

    Every Debian layer starts `RUN /bin/sh -c` and every buildkit entry ends
    `# buildkit`; both are constant, so they carry no information and only
    push the part that differs off the line.
    """

    def test_the_shell_wrapper_is_stripped_from_run_steps(self):
        verb, detail = build_step("RUN /bin/sh -c apt-get update && apt-get install -y curl")
        self.assertEqual(verb, "RUN")
        self.assertEqual(detail, "apt-get update && apt-get install -y curl")

    def test_the_buildkit_marker_is_stripped(self):
        verb, detail = build_step("COPY docker-entrypoint.sh /usr/local/bin/ # buildkit")
        self.assertEqual(verb, "COPY")
        self.assertEqual(detail, "docker-entrypoint.sh /usr/local/bin/")

    def test_tabs_and_newlines_collapse_to_single_spaces(self):
        """buildkit embeds real tabs, which otherwise wreck the alignment."""
        _, detail = build_step("RUN /bin/sh -c set -eux; \t\tapt-get update; \n\tapt-get clean")
        self.assertNotIn("\t", detail)
        self.assertNotIn("\n", detail)
        self.assertIn("set -eux; apt-get update; apt-get clean", detail)

    def test_base_image_layers_are_labelled(self):
        verb, detail = build_step("# debian.sh --arch 'amd64' out/ 'bookworm'")
        self.assertEqual(verb, "BASE")
        self.assertTrue(detail.startswith("debian.sh"))

    def test_other_verbs_are_recognised(self):
        for text, want in (
            ("WORKDIR /app", "WORKDIR"),
            ("ADD file.tar.gz / # buildkit", "ADD"),
            ("USER node", "USER"),
        ):
            self.assertEqual(build_step(text)[0], want, text)

    def test_an_unrecognised_command_is_passed_through(self):
        verb, detail = build_step("something unexpected")
        self.assertEqual(verb, "")
        self.assertEqual(detail, "something unexpected")

    def test_an_empty_command_does_not_crash(self):
        self.assertEqual(build_step(""), ("", ""))

    def test_a_digest_is_shortened_but_keeps_its_algorithm(self):
        full = "sha256:" + "4da4fc9c4800" + "0" * 52
        self.assertEqual(short_digest(full), "sha256:4da4fc9c4800")
        # A value with no algorithm prefix must not lose its head.
        self.assertEqual(short_digest("abcdef123456789", 6), "abcdef")


if __name__ == "__main__":
    unittest.main(verbosity=2)
