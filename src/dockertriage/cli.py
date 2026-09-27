"""The command-line interface.

A presentation layer only: every behaviour it exposes is implemented in the
core modules, which stay importable without ever touching this file.

    dt alpine:3.19            # pull is implied
    dt inspect python:3.12-slim
    dt inspect --digests alpine:3.19
"""

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import batch, coverage, puller
from . import verify as verify_core
from .constants import BATCH_OUTPUT_DIR
from .humanize import (
    BAR_W,
    INDEX_W,
    SIZE_W,
    build_step,
    human_bytes,
    one_line,
    short_digest,
    size_bar,
)
from .manifest import resolve_layers
from .reference import parse_image
from .registry import RegistryClient
from .version import __version__

__all__ = ["app", "main"]

app = typer.Typer(
    name="dockertriage",
    help="Download a Docker image and extract its full rootfs to a folder.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    # Click only wires up --help by default; every flag here carries a short
    # form, so -h should work too.
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console(stderr=True)
stdout = Console()

# Typer consumes typer.Exit internally even with standalone_mode=False, so the
# exit code cannot be recovered from the exception. Commands record it here.
_exit_code = 0


def _fail(message: str, code: int = 1) -> typer.Exit:
    """Print an error, remember the exit code, and build the Exit to raise."""
    global _exit_code
    _exit_code = code
    console.print(f"[red]error:[/red] {message}")
    return typer.Exit(code)


def _version_callback(value: bool) -> None:
    if value:
        stdout.print(f"dt {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Pull container images without Docker, a daemon, or root."""


def _split_platform(platform: str | None, os_name: str, arch: str) -> tuple[str, str]:
    if not platform:
        return os_name, arch
    if "/" not in platform:
        raise typer.BadParameter("platform must look like linux/amd64", param_hint="--platform")
    target_os, _, target_arch = platform.partition("/")
    if not target_os or not target_arch:
        raise typer.BadParameter("platform must look like linux/amd64", param_hint="--platform")
    return target_os, target_arch


@app.command()
def pull(
    ctx: typer.Context,
    image: str | None = typer.Argument(
        None,
        help="alpine:3.19 | nginx@sha256:... | https://hub.docker.com/r/org/repo",
        show_default=False,
    ),
    list_file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        help="File of image references, one per line ([cyan]-[/cyan] for stdin).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Parent directory for the extracted folders "
        "[dim](default: . for one image, ./output for --file)[/dim].",
    ),
    dest: Path | None = typer.Option(
        None,
        "--dest",
        "-d",
        help="Exact destination folder, overriding the generated name.",
    ),
    jobs: int = typer.Option(
        8,
        "--jobs",
        "-j",
        min=1,
        max=64,
        help="Parallel layer downloads [dim]within[/dim] one image.",
    ),
    concurrency: int = typer.Option(
        1,
        "--concurrency",
        "-c",
        min=1,
        max=32,
        help="Images pulled at once when using [cyan]--file[/cyan].",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        "-r",
        help="Write a JSON summary of a batch run to this path.",
    ),
    stop_on_error: bool = typer.Option(
        False,
        "--stop-on-error",
        "-e",
        help="Abort the batch on the first failure instead of continuing.",
    ),
    no_budget_check: bool = typer.Option(
        False,
        "--no-budget-check",
        "-b",
        help="Skip the Docker Hub rate-limit preflight.",
    ),
    strict_tag: bool = typer.Option(
        False,
        "--strict-tag",
        "-t",
        help="Fail if [cyan]latest[/cyan] is missing instead of using the newest tag.",
    ),
    platform: str | None = typer.Option(
        None,
        "--platform",
        "-p",
        help="Target platform as os/arch, e.g. [cyan]linux/arm64[/cyan].",
    ),
    os_name: str = typer.Option("linux", "--os", "-O", help="Target OS."),
    arch: str = typer.Option("amd64", "--arch", "-a", help="Target architecture."),
    path: list[str] = typer.Option(
        [],
        "--path",
        "-P",
        help="Keep only this path from the image. Repeatable, e.g. "
        "[cyan]-P /app -P /etc/nginx[/cyan].",
    ),
    app: bool = typer.Option(
        False,
        "--app",
        "-W",
        help="Keep only the image's [cyan]WorkingDir[/cyan], where the app lives.",
    ),
    keep_tar: bool = typer.Option(
        False,
        "--keep-tar",
        "-k",
        help="Keep raw layer tarballs under [cyan].layers/[/cyan].",
    ),
    verify: bool = typer.Option(
        True,
        "--verify/--no-verify",
        "-y/-n",
        help="Check each layer blob against its manifest sha256.",
    ),
    check: bool = typer.Option(
        True,
        "--check/--no-check",
        "-x/-X",
        help="After pulling, confirm each image really landed on disk.",
    ),
    check_access: bool = typer.Option(
        True,
        "--check-access/--no-check-access",
        "-A/-N",
        help="Before pulling, find which images are private, deleted, or taken down.",
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        "-D",
        help="Make [cyan]--check[/cyan] re-count the whole extracted tree.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Download one image, or every image in a file, and extract the rootfs."""
    global _exit_code

    # Typer releases disagree about the exit status produced by
    # ``no_args_is_help``.  Handle the unfinished command ourselves so
    # ``dt pull`` consistently teaches the syntax while still reporting a
    # usage error to scripts on every supported Python version.
    if image is None and list_file is None:
        _exit_code = 2
        typer.echo(ctx.get_help())
        raise typer.Exit(2)

    target_os, target_arch = _split_platform(platform, os_name, arch)

    # Usage errors exit 2, the same as argparse's parser.error, so scripts
    # can tell "you typed it wrong" from "the pull failed".
    if image and list_file:
        raise _fail("pass an image or --file, not both", 2)
    if list_file and dest:
        raise _fail("--dest takes one image; use --output with --file", 2)
    if list_file and (path or app):
        raise _fail("--path/--app take one image, not --file", 2)

    if list_file:
        # A list of images means a pile of folders; keeping them out of the
        # working directory by default is the only sane thing to do.
        _pull_batch(
            list_file,
            output if output is not None else Path(BATCH_OUTPUT_DIR),
            jobs,
            concurrency,
            report,
            stop_on_error,
            target_os,
            target_arch,
            keep_tar,
            verify,
            quiet,
            strict_tag,
            not no_budget_check,
            check,
            deep,
            check_access,
        )
        return

    assert image is not None
    try:
        # `dest_path` rather than `path`: the --path option owns that name now.
        dest_path = puller.pull(
            image,
            str(output if output is not None else Path(".")),
            jobs=jobs,
            os_name=target_os,
            arch=target_arch,
            keep_tar=keep_tar,
            quiet=quiet,
            dest_override=str(dest) if dest else None,
            verify=verify,
            strict_tag=strict_tag,
            paths=path,
            use_workdir=app,
        )
    except KeyboardInterrupt:
        _exit_code = 130
        console.print("[yellow]interrupted[/yellow]")
        raise typer.Exit(130) from None
    except (ValueError, RuntimeError, OSError) as exc:
        raise _fail(str(exc)) from None

    if check:
        # Verification runs on every pull. Show what it actually inspected,
        # because "verified" with nothing behind it is just a word.
        outcome = verify_core.verify_dest(dest_path, image=image, quick=not deep)
        if not quiet:
            console.print(f"[dim]verifying ({outcome.depth}):[/dim]")
            for line in outcome.explain():
                colour = "green" if line.startswith("ok") else "red"
                console.print(f"  [{colour}]{line}[/{colour}]")
        if not outcome.ok:
            raise _fail(f"{image} did not verify: {'; '.join(outcome.problems)}")
        if not quiet:
            console.print(f"[green]verified: {outcome.summary()}[/green]")

    # Plain stdout so `$(dt pull alpine -q)` stays scriptable.
    print(dest_path)


def _pull_batch(
    list_file: Path,
    output: Path,
    jobs: int,
    concurrency: int,
    report: Path | None,
    stop_on_error: bool,
    target_os: str,
    target_arch: str,
    keep_tar: bool,
    verify: bool,
    quiet: bool,
    strict_tag: bool,
    check_budget: bool,
    check: bool = True,
    deep: bool = False,
    check_access: bool = True,
) -> None:
    """Batch half of `pull`, kept separate so each path stays readable."""
    global _exit_code
    try:
        images = batch.read_image_list(str(list_file))
    except OSError as exc:
        raise _fail(str(exc)) from None
    if not images:
        raise _fail(f"no image references found in {list_file}")

    try:
        results = batch.pull_many(
            images,
            str(output),
            jobs=jobs,
            os_name=target_os,
            arch=target_arch,
            keep_tar=keep_tar,
            quiet=quiet,
            verify=verify,
            concurrency=concurrency,
            stop_on_error=stop_on_error,
            strict_tag=strict_tag,
            check_budget=check_budget,
            verify_pulls=check,
            deep_verify=deep,
            check_access=check_access,
        )
    except KeyboardInterrupt:
        _exit_code = 130
        console.print("[yellow]interrupted[/yellow]")
        raise typer.Exit(130) from None

    # Images the preflight found were never downloadable. Distinguished from
    # failures throughout, because the user's response to each is different.
    skipped = [r for r in results if r.skipped]

    if report:
        payload = {
            "total": len(images),
            "ok": sum(1 for r in results if r.ok),
            "failed": sum(1 for r in results if not r.ok),
            "verified": sum(1 for r in results if r.verified),
            # Never downloadable: private, deleted, taken down, or no such
            # tag. Separated from 'failed' because the fix is different.
            "skipped_inaccessible": len(skipped),
            "unattempted": len(images) - len(results),
            "results": [r.as_dict() for r in results],
        }
        try:
            report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            raise _fail(f"could not write report: {exc}") from None

    # pull_many already streams one line per image and prints the run summary
    # (ok/failed tally, verified-on-disk count, skip-list location) to stderr
    # as it goes. Re-printing a full table and the same tallies here is what
    # made a 100-image run unreadable, so the CLI adds nothing to stderr and
    # only emits the machine-facing destination paths on stdout.
    for r in results:
        if r.ok and r.dest:
            print(r.dest)

    failed = [r for r in results if not r.ok]
    if failed or len(results) != len(images):
        _exit_code = 1
        raise typer.Exit(1)


@app.command(name="verify")
def verify_cmd(
    target: Path | None = typer.Argument(
        None,
        help="Folder holding the extracted images [dim](default: ./output)[/dim].",
        show_default=False,
    ),
    list_file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        help="The image list that was pulled, so images that never arrived are caught.",
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        "-D",
        help="Re-count every file instead of trusting the completion marker.",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        "-r",
        help="Write a JSON summary of the verification to this path.",
    ),
    failed_only: bool = typer.Option(
        False,
        "--failed-only",
        "-F",
        help="Print only the images that did not verify.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the table."),
) -> None:
    """Confirm downloaded images are complete, and say which ones are not.

    With [cyan]--file[/cyan] the answer starts from the list you asked for,
    so an image that was never downloaded is reported as missing instead of
    quietly not being counted. Without it, every folder present is checked.
    """
    global _exit_code
    out_dir = str(target) if target is not None else BATCH_OUTPUT_DIR

    if list_file:
        try:
            images = batch.read_image_list(str(list_file))
        except OSError as exc:
            raise _fail(str(exc)) from None
        if not images:
            raise _fail(f"no image references found in {list_file}")
        results = verify_core.verify_list(images, out_dir, quick=not deep)
    else:
        try:
            results = verify_core.verify_output_dir(out_dir, quick=not deep)
        except OSError as exc:
            raise _fail(str(exc)) from None
        if not results:
            raise _fail(f"no extracted images found in {out_dir}")

    bad = [r for r in results if not r.ok]

    if report:
        payload = {
            "total": len(results),
            "verified": len(results) - len(bad),
            "failed": len(bad),
            "deep": deep,
            "output": os.path.abspath(out_dir),
            "results": [r.as_dict() for r in results],
        }
        try:
            report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            raise _fail(f"could not write report: {exc}") from None

    shown = bad if failed_only else results
    if not quiet and shown:
        console.print(
            f"\n[bold]{len(results)} images[/bold] [dim]({'deep' if deep else 'quick'} check)[/dim]"
        )
        table = Table.grid(padding=(0, 2))
        table.add_column(width=6)
        table.add_column(overflow="fold")
        table.add_column()
        table.add_column(justify="right")
        table.add_column(overflow="fold")
        table.add_row(
            "[dim]state[/dim]",
            "[dim]image[/dim]",
            "[dim]status[/dim]",
            "[dim]checks[/dim]",
            "[dim]detail[/dim]",
        )
        for r in shown:
            passed = sum(1 for c in r.checks if c.passed)
            table.add_row(
                "[green]ok[/green]" if r.ok else "[red]FAIL[/red]",
                r.image,
                r.status,
                f"{passed}/{len(r.checks)}",
                "; ".join(r.problems) if r.problems else (r.dest or ""),
            )
        console.print(table)
        # Name the checks themselves once, so the counts above mean something.
        names = []
        for r in results:
            for c in r.checks:
                if c.name not in names:
                    names.append(c.name)
        if names:
            console.print("[dim]checks performed per image:[/dim]")
            width = max(len(n) for n in names)
            for name in names:
                why = verify_core.CHECK_HELP.get(name, "")
                line = f"  {name:<{width}}  {why}".rstrip()
                console.print(f"[dim]{line}[/dim]")

    verified = len(results) - len(bad)
    colour = "green" if not bad else "red"
    console.print(f"[{colour}]{verified}/{len(results)} images verified[/{colour}]")

    # Failed images go to stdout so the list can be piped straight back in:
    #   dt verify -f images.txt --failed-only -q > retry.txt && dt -f retry.txt
    for r in bad:
        print(r.image)

    if bad:
        _exit_code = 1
        raise typer.Exit(1)


@app.command()
def inspect(
    image: str = typer.Argument(..., help="Image reference to inspect.", show_default=False),
    platform: str | None = typer.Option(
        None, "--platform", "-p", help="Target platform as os/arch."
    ),
    os_name: str = typer.Option("linux", "--os", "-O", help="Target OS."),
    arch: str = typer.Option("amd64", "--arch", "-a", help="Target architecture."),
    digests: bool = typer.Option(
        False,
        "--digests",
        "-D",
        help="Print layer digests one per line for scripting, instead of the table.",
    ),
    no_budget_check: bool = typer.Option(
        False,
        "--no-budget-check",
        "-b",
        help="Skip the Docker Hub rate-limit preflight.",
    ),
    strict_tag: bool = typer.Option(
        False,
        "--strict-tag",
        "-t",
        help="Fail if [cyan]latest[/cyan] is missing instead of using the newest tag.",
    ),
) -> None:
    """Show an image's layers and size without downloading them.

    By default this prints a table of layer sizes and build commands for a
    human to read. Pass [cyan]--digests[/cyan] to print just the layer
    digests, one per line, which is easy to pipe into another command.
    """
    target_os, target_arch = _split_platform(platform, os_name, arch)
    ref = parse_image(image)
    client = RegistryClient(ref)
    try:
        found, config = resolve_layers(client, target_os, target_arch, strict_tag)
    except (ValueError, RuntimeError, OSError) as exc:
        raise _fail(str(exc)) from None
    finally:
        client.close()

    # Script-friendly mode: bare digests on stdout, nothing to parse around.
    if digests:
        for layer in found:
            print(layer.digest)
        return

    _print_inspect(ref, found, config, target_os, target_arch)


# A colour per build verb. Layers that add content are the ones worth finding
# in a wall of RUN steps, so COPY and ADD get the bright colours.
_VERB_STYLE = {
    "COPY": "bright_cyan",
    "ADD": "bright_cyan",
    "RUN": "yellow",
    "WORKDIR": "magenta",
    "BASE": "blue",
}


def _print_inspect(ref, layers, config: dict, target_os: str, target_arch: str) -> None:
    """Render an image's layers without box-drawing noise.

    A bordered table spends three characters per column on rules and wraps a
    long digest across lines. Alignment alone separates the columns just as
    well, which leaves the width for content.
    """
    # Repo and tag on their own lines: a digest reference is 71 characters, so
    # keeping it on the name's line guarantees an ugly wrap.
    stdout.print(f"\n[bold]{ref.repo}[/bold]")
    if ref.is_digest:
        stdout.print(f"[dim]@[/dim][cyan]{short_digest(ref.ref, 16)}[/cyan] [dim]digest[/dim]")
    else:
        stdout.print(f"[dim]:[/dim][cyan]{ref.ref}[/cyan]")
    stdout.print(f"[dim]{target_os}/{target_arch}[/dim]\n")

    # Laid out by hand rather than with a Table. The columns here are all
    # fixed width except the last, so computing the remaining space directly
    # is simpler than persuading a table layout to do it, and it guarantees
    # the step text is truncated to fit instead of running off the edge.
    # The widths come from humanize so `dt pull` draws its rows identically.
    width = max(60, min(stdout.width, 120))
    step_w = width - (INDEX_W + SIZE_W + BAR_W + 4)  # 4 = single spaces between

    stdout.print(f"[dim]{'#':>{INDEX_W}} {'size':>{SIZE_W}} {'':<{BAR_W}} step[/dim]")

    largest = max((layer.size for layer in layers), default=0)
    for i, layer in enumerate(layers, start=1):
        verb, detail = build_step(layer.command or "")
        if not (layer.command or "").strip():
            verb, detail = "", short_digest(layer.digest)

        # Truncate before adding markup, or the tags themselves get counted
        # as visible characters and the line comes out short.
        room = step_w - (len(verb) + 1 if verb else 0)
        text = one_line(detail, max(10, room))
        style = _VERB_STYLE.get(verb, "white")
        step = f"[{style}]{verb}[/{style}] {text}" if verb else text

        stdout.print(
            f"[dim]{i:>{INDEX_W}}[/dim] "
            f"{human_bytes(layer.size):>{SIZE_W}} "
            f"[dim]{size_bar(layer.size, largest)}[/dim] "
            f"{step}"
        )

    image_cfg = config.get("config") or {}
    total = human_bytes(sum(layer.size for layer in layers))
    plural = "layer" if len(layers) == 1 else "layers"
    stdout.print(f"\n[bold]{len(layers)}[/bold] {plural}  [bold]{total}[/bold] compressed")

    # Runtime facts, one per line, so nothing has to wrap mid-value.
    for label, value in (
        ("entrypoint", image_cfg.get("Entrypoint")),
        ("cmd", image_cfg.get("Cmd")),
        ("user", image_cfg.get("User")),
    ):
        if value:
            shown = " ".join(value) if isinstance(value, list) else str(value)
            stdout.print(f"[dim]{label:<11}[/dim]{shown}")

    # Where the application lives, which is what makes `--app` an informed
    # choice rather than a guess.
    workdir = coverage.working_dir(config)
    if workdir:
        stdout.print(
            f"[dim]{'workdir':<11}[/dim][cyan]{workdir}[/cyan] [dim]-> dt pull --app[/dim]"
        )
    else:
        stdout.print(f"[dim]{'workdir':<11}not set by this image[/dim]")
    stdout.print("")


def main(args: list[str] | None = None) -> int:
    """Run the Typer app and return an exit code instead of raising SystemExit.

    `dt alpine:3.19` with no subcommand is treated as `dt pull alpine:3.19`,
    so the common case stays one word shorter. `dt -f images.txt` gets the
    same treatment: batch mode is a `pull` with a list instead of one image,
    and requiring the subcommand there would be a pointless distinction.
    """
    global _exit_code
    _exit_code = 0
    argv = list(args) if args is not None else sys.argv[1:]
    # No arguments is a request for help, not an error worth exit 1.
    if not argv:
        argv = ["--help"]
    commands = {"pull", "inspect", "verify"}
    # App-level flags must keep reaching the app, not get shoved into `pull`.
    app_level = {"--help", "-h", "--version", "-V"}
    if argv and argv[0] not in commands and argv[0] not in app_level:
        argv = ["pull", *argv]
    try:
        app(args=argv, standalone_mode=False)
    except SystemExit as exc:  # --help and friends exit through here
        return int(exc.code or 0)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except typer.Abort:
        console.print("[yellow]interrupted[/yellow]")
        return 130
    except Exception as exc:
        # Usage errors from the vendored click layer carry their own exit code
        # and know how to render themselves.
        show = getattr(exc, "show", None)
        code = getattr(exc, "exit_code", None)
        if callable(show) and isinstance(code, int):
            show()
            return code
        raise
    return _exit_code


if __name__ == "__main__":  # pragma: no cover - convenience only
    sys.exit(main())
