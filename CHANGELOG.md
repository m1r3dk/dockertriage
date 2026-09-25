# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [1.1.0] - 2026-09-25

### Added
- **Check which images are reachable before downloading any of them.** A list
  of a few hundred Docker Hub references always contains some that are
  private, deleted, or taken down, and finding that out one download at a
  time buries the real progress. Batch runs now ask the registry about the
  whole list first:

  ```
  checking access for 7 images (no pull budget used)...
    3/7 accessible, 4 not (1.7s)
      3 private, deleted, or taken down
      1 tag does not exist
  ```

  Only the reachable images are downloaded. The unreachable ones are never
  attempted, are reported as `skip` rather than `FAIL` because nothing went
  wrong with the download, and their names are written to
  `output/not-downloaded.txt` with the reason for each. That file is itself a
  valid image list, so `dt -f output/not-downloaded.txt` retries them once the
  repos come back.

  The check spends no pull budget: it reads the access claim in the token the
  registry issues, then sends a HEAD for the manifest. Measured against Docker
  Hub's own counter, the remaining count does not move. An unreachable repo
  costs a single request, since the token alone already settles it. On the
  122-image list of real Docker Hub URLs, this is
  `105/122 accessible, 17 not, in 8.8s` with zero quota consumed; every
  verdict was cross-checked against real manifest resolution with no false
  positives and no false negatives.
  A missing `latest` is deliberately not treated as unreachable, since the
  pull falls back to the newest real tag. Disable with `-N`
  (`--no-check-access`); a single image skips the pass anyway.
- Batch reports (`-r`) gained `skipped_inaccessible`, and each skipped image
  carries `access_status` plus `skipped: true`. Every image from the input
  list appears in `results` either way, so the report is never shorter than
  the list it answers.

### Added
- **`dt verify`: proof that every image actually downloaded.** Pulling a few
  hundred images produces more output than anyone reads, and the failures that
  matter are quiet: an interrupted run, a disk that filled at image 380, a
  folder that lost files being copied elsewhere. Batch runs now end with
  `120/122 verified on disk`, and `dt verify` re-answers the question at any
  time, long after the terminal is gone.
  - `dt verify ./output` checks every extracted folder present.
  - `dt verify ./output -f images.txt` checks against the list you asked for,
    so an image that never downloaded is reported as **missing** rather than
    being invisible for lack of a folder.
  - `--deep` re-counts the whole tree instead of trusting the completion
    marker, which catches files lost after the pull.
  - `-r report.json` writes the outcome per image; `-F -q` prints just the
    failures to stdout, so a retry is `dt verify ... -F -q > retry.txt &&
    dt -f retry.txt`. Exit code is 1 if anything failed to verify.
- Every pull now records a census of the extracted tree (files, dirs,
  symlinks, bytes) in `.image.json`, which is what `--deep` compares against.
- **Verification says what it checked.** A silent "verified" is
  indistinguishable from a verification that did nothing, so every check now
  names itself and the evidence behind it:

  ```
  verifying (deep):
    ok   file count        90 == 90
    ok   dir count         101 == 101
    ok   symlink count     335 == 335
    ok   byte count        7393371 == 7393371
  verified: 8/8 checks passed (deep)
  ```

  Batch runs state the method once up front, then carry `5/5 checks passed`
  on each line. `dt verify` gained a `checks` column plus a legend describing
  what every check inspects. Reports include the individual checks, so a JSON
  consumer can show its working too. `-q` suppresses all of it.

### Changed
- `.image.json` is written atomically and carries `"complete": true`, written
  only after the last layer is extracted. Its presence is now a real
  completion marker rather than a file that might have been half-written when
  a run was killed.
- A batch image counts as `ok` only if its folder is verifiable on disk. A
  pull that returned a path but left nothing behind used to be reported as
  success; it is now a failure, because the point of the tally is to not have
  to trust the log. Use `-X` to turn the check off.
- Batch reports (`-r`) gained `verified`, `unattempted`, and per-image
  `verify_status` / `verify_problems`.

### Changed
- Batch mode (`dt -f list.txt`) now extracts into `./output/` by default
  instead of the working directory, so a list of images no longer scatters
  hundreds of rootfs folders next to your files. `-o` still overrides it, and
  a single-image pull still defaults to the current directory.

### Fixed
- Pull progress no longer prints a blank line after each already-downloaded
  layer. The in-place download line is now closed exactly once, when one is
  actually on screen.
- Layer commands from buildkit no longer dump raw tabs and newlines into the
  output. A shared `humanize.one_line` helper collapses whitespace and
  truncates, used by both the pull log and `dt inspect`.

### Removed
- **The argparse CLI.** There were two front-ends kept in sync by hand, and
  they drifted. Typer is now the only interface and a required dependency.
  `DT_NO_TYPER` and the `[cli]` extra are gone; `pip install dockertriage`
  installs a working `dt`.

### Changed
- **Restructured from a single file into a `src/` package.** `dockertriage.py`
  and `cli.py` are gone; the code now lives in `src/dockertriage/` split by
  responsibility (reference, registry, manifest, extract, puller, batch,
  ratelimit) with the two CLIs under `dockertriage.cli`. Public API is
  unchanged: `from dockertriage import pull` and `dt` both behave as before.
- `python -m dockertriage` now works.
- Moved the sample image list from `final` to `examples/images.txt`.
- Added project URLs, ruff and pytest configuration to `pyproject.toml`, and
  made the version dynamic from `dockertriage/version.py`.

### Fixed
- Installing the wheel no longer puts a generic `cli` module into
  site-packages, where it would collide with other packages.
- `test_stop_message_names_unattempted_images` no longer fails on machines
  that export real `DOCKERHUB_TOKEN` credentials.
- `dt layers` raised `NameError: strict_tag` on every invocation. The command
  never had the flag its body referenced; it now does.
- The undefined-name test compared against `__builtins__`, which is a module
  under `python tests/test_cli.py` but a dict under pytest. It passed one way
  and failed the other; it now uses the `builtins` module explicitly.

### Added
- A `dev` dependency group (pytest, ruff), so `uv sync` then `uv run pytest`
  works from a clean checkout. Documented `uv run` and `uvx` in the README.

### Notes
- `import dockertriage` still touches nothing outside the standard library.
  Typer stops at `cli.py`, and a test plus a CI job enforce that, so embedding
  the library does not drag in a CLI you never call.

### Added
- CI now builds the wheel and asserts the installed console script runs with
  no extras and leaks no top-level modules.
- The stdlib-only guarantee is checked across every module rather than one file.
- A test that executes each typer command body, which is how the `dt layers`
  bug below was found.

## [1.0.0]

- First release. Single-file, dependency-free image pull and rootfs extraction.
