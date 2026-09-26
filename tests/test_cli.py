#!/usr/bin/env python3
"""Tests for the CLI (dockertriage.cli).

Typer is a hard dependency, so nothing here is conditional.

    python3 -m pytest tests/test_cli.py
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

import typer
from typer.testing import CliRunner

import dockertriage as core
from dockertriage import batch as batch_mod
from dockertriage import cli as cli_mod
from dockertriage import puller as puller_mod


class TestTyperCLI(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self._real_pull = puller_mod.pull

    def tearDown(self):
        puller_mod.pull = self._real_pull

    def _stub_pull(self, capture: dict):
        def fake(image, output, **kw):
            capture["image"] = image
            capture["output"] = output
            capture.update(kw)
            return "/tmp/fake-dest"

        puller_mod.pull = fake

    # These tests stub the pull, so there is no real folder to verify; -X
    # turns off the post-pull disk check, which has its own tests below.
    # -- wiring ---------------------------------------------------------
    def test_pull_forwards_arguments_to_core(self):
        seen: dict = {}
        self._stub_pull(seen)
        result = self.runner.invoke(
            cli_mod.app,
            ["pull", "alpine:3.19", "-o", "/tmp/out", "-j", "4", "--keep-tar", "-X"],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(seen["image"], "alpine:3.19")
        self.assertEqual(seen["jobs"], 4)
        self.assertTrue(seen["keep_tar"])

    def test_dest_path_goes_to_stdout(self):
        self._stub_pull({})
        result = self.runner.invoke(cli_mod.app, ["pull", "alpine", "-q", "-X"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("/tmp/fake-dest", result.output)

    def test_platform_splits_into_os_and_arch(self):
        seen: dict = {}
        self._stub_pull(seen)
        result = self.runner.invoke(
            cli_mod.app, ["pull", "alpine", "--platform", "linux/arm64", "-X"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual((seen["os_name"], seen["arch"]), ("linux", "arm64"))

    def test_verify_defaults_on_and_can_be_disabled(self):
        seen: dict = {}
        self._stub_pull(seen)
        self.runner.invoke(cli_mod.app, ["pull", "alpine"])
        self.assertTrue(seen["verify"])

        seen.clear()
        self._stub_pull(seen)
        self.runner.invoke(cli_mod.app, ["pull", "alpine", "--no-verify"])
        self.assertFalse(seen["verify"])

    # -- validation -----------------------------------------------------
    def test_malformed_platform_is_usage_error(self):
        result = self.runner.invoke(cli_mod.app, ["pull", "alpine", "--platform", "linux-arm64"])
        self.assertEqual(result.exit_code, 2)

    def test_platform_missing_arch_rejected(self):
        result = self.runner.invoke(cli_mod.app, ["pull", "alpine", "--platform", "linux/"])
        self.assertEqual(result.exit_code, 2)

    def test_jobs_below_one_rejected(self):
        result = self.runner.invoke(cli_mod.app, ["pull", "alpine", "-j", "0"])
        self.assertEqual(result.exit_code, 2)

    def test_missing_image_is_usage_error(self):
        result = self.runner.invoke(cli_mod.app, ["pull"])
        self.assertEqual(result.exit_code, 2)

    def test_no_args_shows_help(self):
        result = self.runner.invoke(cli_mod.app, [])
        self.assertIn("pull", result.output)

    # -- failures -------------------------------------------------------
    def test_core_failure_becomes_exit_1(self):
        def boom(*a, **k):
            raise RuntimeError("tag/digest not found")

        puller_mod.pull = boom
        result = self.runner.invoke(cli_mod.app, ["pull", "alpine:nope"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("error", result.output.lower())

    def test_keyboard_interrupt_becomes_exit_130(self):
        def interrupted(*a, **k):
            raise KeyboardInterrupt

        puller_mod.pull = interrupted
        result = self.runner.invoke(cli_mod.app, ["pull", "alpine"])
        self.assertEqual(result.exit_code, 130)

    # -- metadata -------------------------------------------------------
    def test_version_matches_core(self):
        result = self.runner.invoke(cli_mod.app, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(core.__version__, result.output)

    def test_commands_are_registered(self):
        result = self.runner.invoke(cli_mod.app, ["--help"])
        for command in ("pull", "inspect", "layers"):
            self.assertIn(command, result.output)


@contextlib.contextmanager
def quiet():
    """Swallow stdout/stderr: these tests assert on exit codes, not output."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


class TestBareImageShortcut(unittest.TestCase):
    """`dt alpine:3.19` should mean `dt pull alpine:3.19`."""

    def setUp(self):
        self._real_pull = puller_mod.pull
        self.seen: dict = {}

        def fake(image, output, **kw):
            self.seen["image"] = image
            self.seen.update(kw)
            return "/tmp/fake-dest"

        puller_mod.pull = fake

    def tearDown(self):
        puller_mod.pull = self._real_pull

    def test_bare_image_is_treated_as_pull(self):
        with quiet():
            rc = cli_mod.main(["alpine:3.19", "-q", "-X"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.seen["image"], "alpine:3.19")

    def test_explicit_pull_still_works(self):
        with quiet():
            rc = cli_mod.main(["pull", "alpine:3.19", "-q", "-X"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.seen["image"], "alpine:3.19")

    def test_subcommand_name_not_swallowed(self):
        with quiet():
            rc = cli_mod.main(["--help"])
        self.assertEqual(rc, 0)
        self.assertNotIn("image", self.seen)


class TestExitCodes(unittest.TestCase):
    """Typer eats typer.Exit internally, so these guard the recorded codes."""

    def setUp(self):
        self._real_pull = puller_mod.pull

    def tearDown(self):
        puller_mod.pull = self._real_pull

    def test_success_returns_zero(self):
        puller_mod.pull = lambda image, output, **kw: "/tmp/ok"
        with quiet():
            self.assertEqual(cli_mod.main(["alpine", "-q", "-X"]), 0)

    def test_runtime_error_returns_one(self):
        def boom(*a, **k):
            raise RuntimeError("tag/digest not found")

        puller_mod.pull = boom
        with quiet():
            self.assertEqual(cli_mod.main(["alpine:nope", "-q"]), 1)

    def test_usage_error_returns_two(self):
        with quiet():
            self.assertEqual(cli_mod.main(["alpine", "--platform", "bogus"]), 2)

    def test_exit_code_resets_between_invocations(self):
        def boom(*a, **k):
            raise RuntimeError("fail")

        puller_mod.pull = boom
        with quiet():
            self.assertEqual(cli_mod.main(["alpine", "-q"]), 1)
        puller_mod.pull = lambda image, output, **kw: "/tmp/ok"
        with quiet():
            self.assertEqual(cli_mod.main(["alpine", "-q", "-X"]), 0, "stale exit code leaked")


class TestVerifyCommand(unittest.TestCase):
    """`dt verify` is how a user answers "did all of them download?".

    Everything here is filesystem-only: no network, no stubbed puller.
    """

    def setUp(self):
        self.runner = CliRunner()
        self.root = tempfile.mkdtemp(prefix="dt-cli-verify-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _make_image(self, folder, complete=True):
        dest = os.path.join(self.root, folder)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, "file"), "w") as fh:
            fh.write("data")
        meta = {
            "image": folder,
            "layers": [{"digest": "sha256:a", "size": 1}],
            "complete": complete,
            "rootfs": core.scan_tree(dest).as_dict(),
        }
        with open(os.path.join(dest, ".image.json"), "w") as fh:
            json.dump(meta, fh)
        return dest

    def _list_file(self, images):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(images) + "\n")
        self.addCleanup(os.unlink, path)
        return path

    def test_all_good_exits_zero(self):
        self._make_image("library_alpine_3.19")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_incomplete_image_exits_one(self):
        self._make_image("library_alpine_3.19", complete=False)
        result = self.runner.invoke(cli_mod.app, ["verify", self.root])
        self.assertEqual(result.exit_code, 1)

    def test_list_catches_an_image_that_never_arrived(self):
        """The scenario that motivates the command: one of many is absent."""
        self._make_image("library_alpine_3.19")
        path = self._list_file(["alpine:3.19", "redis:7"])
        result = self.runner.invoke(cli_mod.app, ["verify", self.root, "-f", path])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("redis:7", result.output)

    def test_failed_images_go_to_stdout_for_a_retry(self):
        """Piping the failures back into `dt -f` must just work."""
        self._make_image("library_alpine_3.19")
        path = self._list_file(["alpine:3.19", "redis:7"])
        result = self.runner.invoke(
            cli_mod.app, ["verify", self.root, "-f", path, "--failed-only", "-q"]
        )
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        self.assertIn("redis:7", lines)
        self.assertNotIn("alpine:3.19", lines)

    def test_report_is_written_as_json(self):
        self._make_image("library_alpine_3.19")
        report = os.path.join(self.root, "report.json")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root, "-r", report])
        self.assertEqual(result.exit_code, 0, result.output)
        with open(report) as fh:
            payload = json.load(fh)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["verified"], 1)
        self.assertEqual(payload["failed"], 0)

    def test_deep_check_catches_a_deleted_file(self):
        dest = self._make_image("library_alpine_3.19")
        os.remove(os.path.join(dest, "file"))
        # Replace it so the folder is not simply empty, which quick catches.
        with open(os.path.join(dest, "other"), "w") as fh:
            fh.write("xx")
        self.assertEqual(self.runner.invoke(cli_mod.app, ["verify", self.root]).exit_code, 0)
        self.assertEqual(
            self.runner.invoke(cli_mod.app, ["verify", self.root, "--deep"]).exit_code, 1
        )

    def test_empty_output_dir_is_an_error_not_a_silent_pass(self):
        """Verifying nothing must never look like verifying everything."""
        result = self.runner.invoke(cli_mod.app, ["verify", self.root])
        self.assertEqual(result.exit_code, 1)

    def test_verify_is_a_real_subcommand_not_an_image_name(self):
        """`dt verify` must not be rewritten into `dt pull verify`."""
        with quiet():
            code = cli_mod.main(["verify", self.root])
        self.assertEqual(code, 1)  # empty dir, but it reached the command

    # -- showing its working ---------------------------------------------
    def test_table_shows_how_many_checks_ran(self):
        self._make_image("library_alpine_3.19")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root])
        self.assertIn("checks", result.output)

    def test_output_names_the_checks_it_performed(self):
        """A count with no names is still asking the user to take it on faith."""
        self._make_image("library_alpine_3.19")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root])
        self.assertIn("checks performed per image", result.output)
        self.assertIn("pull completed", result.output)

    def test_the_legend_covers_every_check_that_ran(self):
        """A check with no entry in the legend is an unexplained verdict."""
        self._make_image("library_alpine_3.19")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root, "--deep"])
        for name in ("folder exists", "record readable", "file count", "byte count"):
            self.assertIn(name, result.output)
            self.assertIn(core.CHECK_HELP[name], result.output)

    def test_deep_output_names_the_counts_it_compared(self):
        self._make_image("library_alpine_3.19")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root, "--deep"])
        self.assertIn("file count", result.output)
        self.assertIn("symlink count", result.output)

    def test_quiet_suppresses_the_explanation(self):
        """Scripts asked for an exit code, not a lecture."""
        self._make_image("library_alpine_3.19")
        result = self.runner.invoke(cli_mod.app, ["verify", self.root, "-q"])
        self.assertNotIn("checks performed", result.output)


class TestPullShowsItsVerification(unittest.TestCase):
    """A single pull must say how it verified, not just print a path.

    Uses the real puller against a faked registry, so the output asserted
    here is what a user actually sees.
    """

    def setUp(self):
        self.runner = CliRunner()
        self.root = tempfile.mkdtemp(prefix="dt-cli-pullverify-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self._real = (puller_mod.RegistryClient, puller_mod.resolve_layers)

        body = b"hello"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("bin/sh")
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
        raw = buf.getvalue()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        layer = core.Layer(
            index=0,
            digest=digest,
            size=len(raw),
            media_type="application/vnd.oci.image.layer.v1.tar",
            command="RUN echo hi",
        )

        class FakeClient:
            def __init__(self):
                self.image = core.parse_image("example/app:1.0")

            def download_blob(self, d, dest, progress=None, verify=True):
                with open(dest, "wb") as fh:
                    fh.write(raw)
                return dest

            def close(self):
                pass

        puller_mod.RegistryClient = lambda image: FakeClient()
        puller_mod.resolve_layers = lambda c, o, a, strict_tag=False: ([layer], {"config": {}})

    def tearDown(self):
        puller_mod.RegistryClient, puller_mod.resolve_layers = self._real

    def test_pull_prints_what_it_verified(self):
        result = self.runner.invoke(cli_mod.app, ["pull", "example/app:1.0", "-o", self.root])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("verifying", result.output)
        self.assertIn("pull completed", result.output)
        self.assertIn("checks passed", result.output)

    def test_deep_pull_names_the_counts_it_compared(self):
        result = self.runner.invoke(
            cli_mod.app, ["pull", "example/app:1.0", "-o", self.root, "--deep"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("file count", result.output)

    def test_quiet_pull_prints_only_the_path(self):
        """`$(dt alpine -q)` must stay a clean path, explanation or not."""
        result = self.runner.invoke(cli_mod.app, ["pull", "example/app:1.0", "-o", self.root, "-q"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("verifying", result.output)
        lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, f"expected just the path, got {lines}")


class TestSingleEntryPoint(unittest.TestCase):
    """There is exactly one CLI. Nothing may reintroduce a second one."""

    def test_main_is_the_console_script_target(self):
        self.assertTrue(callable(cli_mod.main))
        self.assertEqual(cli_mod.main.__module__, "dockertriage.cli")

    def test_package_exposes_no_rival_cli_module(self):
        import pathlib as _pathlib

        pkg = _pathlib.Path(core.__file__).parent
        names = {p.stem for p in pkg.rglob("*.py")}
        for banned in ("argparse_cli", "typer_cli"):
            self.assertNotIn(banned, names, f"{banned} is back; there must be one CLI")


class TestEveryCommandIsCallable(unittest.TestCase):
    """`dt layers` shipped raising NameError on an undefined local.

    Nothing executed the command bodies, so a typo survived review. Compiling
    each callback against its own signature catches that class of bug without
    needing the network.
    """

    def test_no_command_references_an_undefined_name(self):
        import builtins
        import symtable

        path = cli_mod.__file__
        source = open(path).read()
        top = symtable.symtable(source, path, "exec")
        # `builtins` explicitly, not `__builtins__`: the latter is a module
        # when this file runs as __main__ but a dict when pytest imports it,
        # so dir() would return dict methods and flag every real builtin.
        known = set(dir(cli_mod)) | set(dir(builtins)) | {"__builtins__"}

        def check(table):
            for child in table.get_children():
                if child.get_type() == "function":
                    for sym in child.get_symbols():
                        if sym.is_global() and sym.get_name() not in known:
                            self.fail(
                                f"{child.get_name()}() uses undefined name {sym.get_name()!r}"
                            )
                check(child)

        check(top)

    def test_layers_resolves_without_touching_the_network(self):
        """Run the real command body with the registry stubbed out."""
        captured = {}

        class FakeLayer:
            digest = "sha256:deadbeef"

        def fake_resolve(client, os_name, arch, strict_tag=False):
            captured["strict_tag"] = strict_tag
            return [FakeLayer()], {}

        real_resolve, real_client = cli_mod.resolve_layers, cli_mod.RegistryClient
        cli_mod.resolve_layers = fake_resolve
        cli_mod.RegistryClient = lambda ref: type("C", (), {"close": lambda self: None})()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_mod.main(["layers", "alpine:3.19"])
        finally:
            cli_mod.resolve_layers, cli_mod.RegistryClient = real_resolve, real_client

        self.assertEqual(code, 0)
        self.assertIn("sha256:deadbeef", out.getvalue())
        self.assertIs(captured["strict_tag"], False)


class TestCoreStaysIndependent(unittest.TestCase):
    """typer is required for `dt`, but not for `import dockertriage`.

    Someone embedding the library in their own tool should not pay for a CLI
    they never call, so the dependency stops at cli.py.
    """

    def test_importing_the_library_does_not_import_typer(self):
        import subprocess

        code = (
            "import sys, dockertriage; sys.exit(1 if {'typer', 'rich'} & set(sys.modules) else 0)"
        )
        env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(core.__file__)))
        proc = subprocess.run([sys.executable, "-c", code], env=env)
        self.assertEqual(proc.returncode, 0, "importing dockertriage pulled in typer/rich")

    def test_core_modules_import_no_typer(self):
        """Every core module, not just one file: the rule must survive a split."""
        import ast
        import pathlib

        pkg = pathlib.Path(core.__file__).parent
        checked = 0
        for path in sorted(pkg.rglob("*.py")):
            # cli.py is the one module allowed to import typer.
            if path.name == "cli.py":
                continue
            tree = ast.parse(path.read_text())
            modules = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    modules.add(node.module.split(".")[0])
            for forbidden in ("typer", "click", "rich"):
                self.assertNotIn(forbidden, modules, f"{path.name} must not import {forbidden}")
            checked += 1
        self.assertGreater(checked, 5, "expected to scan the whole package")


class TestFlagContract(unittest.TestCase):
    """The flags `pull` must keep, and the conventions every flag must follow.

    Batch mode once shipped missing its flags entirely because nothing
    asserted the surface. This is that assertion, plus the project rule that
    every long flag carries a unique single-letter short form.
    """

    # Every flag the tool has ever documented. Dropping one is a breaking
    # change, so it has to be a deliberate edit to this list.
    REQUIRED = {
        "--output",
        "--dest",
        "--jobs",
        "--platform",
        "--os",
        "--arch",
        "--keep-tar",
        "--quiet",
        "--file",
        "--concurrency",
        "--report",
        "--stop-on-error",
        "--no-budget-check",
        "--strict-tag",
        "--verify",
        "--no-verify",
        # The post-pull disk check: a pull that cannot be confirmed on disk
        # is not a success, and that promise must not silently disappear.
        "--check",
        "--no-check",
        "--deep",
        # The pre-download reachability pass: without it a list's dead
        # entries cost a full download attempt each to discover.
        "--check-access",
        "--no-check-access",
    }

    def _params(self, command="pull"):
        cmd = typer.main.get_command(cli_mod.app)
        return cmd.commands[command].params

    def _typer_pull_options(self):
        # Typer vendors its own click, so duck-type on secondary_opts rather
        # than importing click, which may not be a top-level module.
        cmd = typer.main.get_command(cli_mod.app)
        pull_cmd = cmd.commands["pull"]
        opts = set()
        for param in pull_cmd.params:
            if not hasattr(param, "secondary_opts"):
                continue
            opts |= {o for o in param.opts if o.startswith("--")}
            opts |= {o for o in param.secondary_opts if o.startswith("--")}
        return opts

    def test_pull_keeps_every_documented_flag(self):
        missing = self.REQUIRED - self._typer_pull_options()
        self.assertEqual(missing, set(), f"`pull` lost: {sorted(missing)}")

    def test_batch_flags_are_present(self):
        for flag in ("--file", "--concurrency", "--report", "--stop-on-error"):
            self.assertIn(flag, self._typer_pull_options())

    def test_every_long_flag_has_a_single_letter_short_form(self):
        missing = []
        for command in ("pull", "inspect", "layers", "verify"):
            for param in self._params(command):
                every = getattr(param, "opts", [])
                opts = [o for o in every if o.startswith("--")]
                shorts = [o for o in every if not o.startswith("--") and o.startswith("-")]
                if opts and not shorts and opts[0] != "--help":
                    missing.append(f"{command} {opts[0]}")
        self.assertEqual(missing, [], f"long flags without a short form: {missing}")

    def test_short_forms_are_unique_within_a_command(self):
        for command in ("pull", "inspect", "layers", "verify"):
            seen = {}
            for param in self._params(command):
                for opt in getattr(param, "opts", []):
                    # Positional arguments carry a bare name, not a flag.
                    if opt.startswith("--") or not opt.startswith("-"):
                        continue
                    self.assertEqual(len(opt), 2, f"{opt} is not a single-letter form")
                    self.assertNotIn(
                        opt, seen, f"{command}: {opt} reused by {param.name} and {seen.get(opt)}"
                    )
                    seen[opt] = param.name


class TestBatchRouting(unittest.TestCase):
    """`dt -f list.txt` must reach batch mode without naming the subcommand."""

    def test_bare_dash_f_routes_to_pull(self):
        seen = {}

        def fake_pull_many(images, out_dir, **kw):
            seen["images"] = list(images)
            seen["concurrency"] = kw.get("concurrency")
            return [core.BatchResult(i, dest=f"/out/{i}") for i in images]

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alpine:3.19\nbusybox:latest\n")
            path = fh.name
        real = batch_mod.pull_many
        batch_mod.pull_many = fake_pull_many
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli_mod.main(["-f", path, "-c", "3", "-q"])
        finally:
            batch_mod.pull_many = real
            os.unlink(path)
        self.assertEqual(code, 0)
        self.assertEqual(seen["images"], ["alpine:3.19", "busybox:latest"])
        self.assertEqual(seen["concurrency"], 3)

    def test_batch_defaults_to_output_folder(self):
        """A list of images must not litter the working directory."""
        seen = {}

        def fake_pull_many(images, out_dir, **kw):
            seen["out_dir"] = out_dir
            return [core.BatchResult(i, dest=f"/out/{i}") for i in images]

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alpine:3.19\n")
            path = fh.name
        real = batch_mod.pull_many
        batch_mod.pull_many = fake_pull_many
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli_mod.main(["-f", path, "-q"])
        finally:
            batch_mod.pull_many = real
            os.unlink(path)
        self.assertEqual(code, 0)
        self.assertEqual(seen["out_dir"], "output")

    def test_batch_output_flag_still_wins(self):
        seen = {}

        def fake_pull_many(images, out_dir, **kw):
            seen["out_dir"] = out_dir
            return [core.BatchResult(i, dest=f"/out/{i}") for i in images]

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alpine:3.19\n")
            path = fh.name
        real = batch_mod.pull_many
        batch_mod.pull_many = fake_pull_many
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cli_mod.main(["-f", path, "-o", "/tmp/elsewhere", "-q"])
        finally:
            batch_mod.pull_many = real
            os.unlink(path)
        self.assertEqual(seen["out_dir"], "/tmp/elsewhere")

    def test_single_image_still_defaults_to_cwd(self):
        seen: dict = {}
        real = puller_mod.pull

        def fake(image, output, **kw):
            seen["output"] = output
            return "/tmp/x"

        puller_mod.pull = fake
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cli_mod.main(["alpine:3.19", "-q"])
        finally:
            puller_mod.pull = real
        self.assertEqual(seen["output"], ".")

    def test_batch_failure_exits_nonzero(self):
        def fake_pull_many(images, out_dir, **kw):
            return [core.BatchResult(i, error="boom") for i in images]

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alpine:3.19\n")
            path = fh.name
        real = batch_mod.pull_many
        batch_mod.pull_many = fake_pull_many
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli_mod.main(["-f", path, "-q"])
        finally:
            batch_mod.pull_many = real
            os.unlink(path)
        self.assertEqual(code, 1)

    def test_image_and_file_together_is_a_usage_error(self):
        # Exit 2 means "you typed it wrong", distinct from 1 ("pull failed").
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli_mod.main(["pull", "alpine", "-f", "list.txt"])
        self.assertEqual(code, 2)

    def test_app_level_flags_still_route(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_mod.main(["--version"]), 0)
            self.assertEqual(cli_mod.main(["-h"]), 0)


class TestHelpfulEmptyInvocations(unittest.TestCase):
    """Running a command with no arguments should teach, not scold.

    `dt pull` used to print a red 'Invalid value' error, which reads as a
    crash for what is really just an unfinished command.
    """

    def test_bare_pull_shows_help_not_an_error(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_mod.main(["pull"])
        text = out.getvalue()
        self.assertEqual(code, 2)
        self.assertIn("Usage:", text)
        self.assertNotIn("Invalid value", text)

    def test_bare_invocation_shows_help_and_exits_zero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_mod.main([])
        self.assertEqual(code, 0)
        self.assertIn("Usage:", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
