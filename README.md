# dockertriage

[![CI](https://github.com/m1r3dk/dockertriage/actions/workflows/ci.yml/badge.svg)](https://github.com/m1r3dk/dockertriage/actions/workflows/ci.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Download Docker and OCI images directly from registries and extract their merged
root filesystem to disk.

**No Docker daemon. No root access. No running containers.**

```bash
dt alpine:3.19
```

## About

`dockertriage` is a small Python CLI for people who need the files inside a
container image, not a running container. It resolves image manifests, downloads
layers, verifies layer digests, applies OCI whiteouts in order, preserves file
modes, symlinks and hardlinks, then writes a normal directory you can inspect
with standard tools.

It is useful for:

- security triage and offline image review
- source and application file extraction from container images
- batch image collection from lists of references
- checking whether images are private, deleted, taken down, or missing
- producing repeatable JSON evidence for automation and audits
- inspecting image layers without installing Docker

Unlike `docker save`, the output is not a stack of layer tarballs. It is the
final merged filesystem the container would see after all layers are applied.

## Features

- Pulls from Docker Hub and Amazon ECR Public
- Accepts tags, digests, registry references, and Docker Hub URLs
- Extracts a complete merged rootfs without Docker
- Downloads layers concurrently and extracts them in layer order
- Verifies every blob against the manifest SHA-256 digest
- Handles OCI whiteouts, opaque directories, hardlinks, symlinks, and read-only directories
- Lets you extract only an app path with `--path` or the image `WorkingDir` with `--app`
- Reports what filtered extraction kept and what it left outside the filter
- Supports batch pulls from image lists with JSON reports
- Includes `dt verify` for quick or deep checks after extraction
- Keeps the importable library stdlib-only, with Typer/Rich used only by the CLI

## Installation

### Recommended: pipx

```bash
pipx install "dockertriage @ git+https://github.com/m1r3dk/dockertriage.git"
```

Run once without installing:

```bash
pipx run --spec "dockertriage @ git+https://github.com/m1r3dk/dockertriage.git" dt alpine:3.19
```

Install from a local checkout:

```bash
git clone https://github.com/m1r3dk/dockertriage.git
pipx install ./dockertriage
```

Upgrade or remove:

```bash
pipx upgrade dockertriage
pipx uninstall dockertriage
```

### pip

```bash
python -m pip install "dockertriage @ git+https://github.com/m1r3dk/dockertriage.git"
```

Or from a local checkout:

```bash
git clone https://github.com/m1r3dk/dockertriage.git
cd dockertriage
python -m pip install .
```

Requirements:

- Python 3.14 or newer
- No Docker installation
- No Docker daemon
- No root privileges

Python 3.14 is required because zstd-compressed layers use the standard-library
`compression.zstd` module.

## Quick start

Pull and extract one image:

```bash
dt alpine:3.19
```

`pull` is implied. This is equivalent:

```bash
dt pull alpine:3.19
```

Choose a parent output directory or an exact destination:

```bash
dt python:3.12-slim -o ./rootfs
dt redis:7 -d ./redis-rootfs
```

Select another platform:

```bash
dt nginx:latest --platform linux/arm64
```

Inspect layers without downloading them:

```bash
dt inspect python:3.12-slim
```

Print only layer digests for scripts:

```bash
dt inspect --digests alpine:3.19
```

Verify extracted images later:

```bash
dt verify ./output
```

## What the output looks like

`dt inspect` shows the resolved image, platform, compressed layer sizes, and the
build step for each layer:

```text
library/alpine
:3.19
linux/amd64

  #     size            step
  1    3.3MB ██████████ ADD alpine-minirootfs-3.19.9-x86_64.tar.gz /

1 layer  3.3MB compressed
cmd        /bin/sh
workdir    not set by this image
```

`dt pull` uses the same layer row format while downloading and extracting:

```text
library/alpine
:3.19
linux/amd64

1 layer  3.3MB compressed  (resolved in 3.05s)

             ██████████ downloading 3.3MB/3.3MB (100%)
  1    3.3MB ██████████ ADD alpine-minirootfs-3.19.9-x86_64.tar.gz /

90 files, 101 dirs, 335 symlinks, 0 hardlinks, 0 whiteouts
done in 4.68s (fetch+extract 1.62s)
```

The final destination path is written to standard output. Progress and details
are written to standard error, so command substitution is safe:

```bash
ROOTFS=$(dt alpine:3.19 -q)
grep -R "example" "$ROOTFS"
```

## Extract only application files

Most container images contain a base OS, package manager files, shared
libraries, certificates, and runtime dependencies. If you only want application
files, filter the extraction.

```bash
dt pull myorg/api:latest --path /app
dt pull myorg/api:latest --app
dt pull myorg/api:latest -P /app -P /etc/nginx
```

- `--path /app` keeps only that path. It can be repeated.
- `--app` keeps the image's declared `WorkingDir`.
- Every layer is still downloaded and applied in order so overwrites and
  whiteouts are handled correctly.
- Only matching files are written to disk.

A filtered pull reports what was kept and what build steps wrote outside the
filter. That prevents a partial extraction from silently looking complete.

```text
keeping only /app
12 files, 3 dirs, 4 symlinks, 0 hardlinks, 0 whiteouts, 763 filtered out
kept app from layer(s) 8, 9, 10
outside the filter: COPY -> /usr/local/bin/docker-entrypoint.sh (layer 5)
outside the filter: COPY -> /etc/nginx/nginx.conf (layer 11)
```

Use `dt inspect` before pulling when you are not sure where the app lives. Look
for `COPY`, `ADD`, and `workdir` lines.

## Why extracted images have many symlinks

Docker images are Linux root filesystems. Symlinks are normal and expected.
Examples include:

- `/bin/sh -> busybox`
- `/usr/bin/python -> python3`
- shared library links under `/lib` and `/usr/lib`
- package-manager shortcuts
- `node_modules/.bin/*` links to package executables

`dockertriage` preserves symlinks instead of flattening them because resolving
or copying targets would change what the container sees at runtime. If you only
care about source code, use `--app` or `--path` and read the filter report for
links that point outside the kept paths.

## Batch downloads

Create an image list:

```text
# images.txt
alpine:3.19
redis:7
python:3.12-slim
https://hub.docker.com/_/nginx
public.ecr.aws/docker/library/ubuntu:24.04
```

Pull every image in the list:

```bash
dt -f images.txt
```

Batch output defaults to `./output/`. Use options to tune concurrency and write
a report:

```bash
dt -f images.txt -o ./rootfs -c 4 -j 8 -r pull-report.json
```

- `-c 4` pulls up to four images at once
- `-j 8` downloads up to eight layers per image
- `-r` writes JSON totals and per-image results

Blank lines, comments, duplicate entries, stray quotes, and trailing commas are
handled automatically.

Before downloading a batch, Docker Hub references are checked for accessibility.
Private, deleted, taken-down, or missing tags are skipped and listed in
`output/not-downloaded.txt`.

Disable that preflight with `--no-check-access` or `-N`.

## Verification

Verification is automatic on every pull.

### Layer verification

Every downloaded blob is streamed through SHA-256. The calculated digest must
match the digest declared by the manifest. This is enabled by default with
`--verify` and can be disabled with `--no-verify`.

### Output verification

After extraction, `.image.json` is written and checked. A quick check confirms:

- destination exists
- `.image.json` parses
- pull is marked complete
- layers are recorded
- rootfs is not empty

Run verification later:

```bash
dt verify ./output
```

Include the original list to catch images that never created an output folder:

```bash
dt verify ./output -f images.txt
```

Use `--deep` to walk the extracted tree and compare file, directory, symlink,
and byte counts against the census recorded at extraction time:

```bash
dt verify ./output --deep
```

Deep verification detects changed aggregate counts. It does not hash every
extracted file, so a same-size content replacement is outside its scope.

## Command reference

| Command | Purpose |
| --- | --- |
| `dt IMAGE` | Pull and extract one image. `pull` is implied. |
| `dt pull IMAGE` | Explicit single-image pull. |
| `dt pull IMAGE --path P` | Extract only path `P` and report coverage. |
| `dt pull IMAGE --app` | Extract only the image's `WorkingDir`. |
| `dt -f FILE` | Preflight, pull, and verify an image list. |
| `dt verify PATH` | Verify previously extracted images. |
| `dt inspect IMAGE` | Show layer sizes and build commands without downloading layers. |
| `dt inspect --digests IMAGE` | Print layer digests, one per line. |
| `dt --help` | Show top-level help. |
| `dt COMMAND --help` | Show command help. |

Run `dt pull --help`, `dt inspect --help`, or `dt verify --help` for the full
option list.

## Credentials and rate limits

Anonymous Docker Hub pulls are rate-limited. Set Docker Hub credentials to raise
the limit or access repositories your account can pull:

```bash
export DOCKERHUB_USERNAME="your-username"
export DOCKERHUB_TOKEN="your-personal-access-token"
dt -f images.txt -c 4
```

Credentials are read only from environment variables. They are not written to
reports or output metadata.

## Python API

```python
from dockertriage import pull, verify_dest

rootfs = pull("alpine:3.19", "./output")
result = verify_dest(rootfs, image="alpine:3.19", quick=False)

if not result.ok:
    raise RuntimeError(result.problems)
```

The library modules use only the Python standard library. CLI dependencies are
loaded only by the CLI.

## Safety and correctness

The extractor handles OCI whiteouts, opaque directories, symlinks, hardlinks,
type transitions between layers, read-only directories, and BuildKit attestation
entries. Archive paths and link targets are confined to the destination.

CI checks include:

- unit and CLI tests on Python 3.14
- offline tests with socket access blocked
- Ruff formatting and linting
- mypy type checking
- wheel build and console-script smoke tests
- macOS and Windows offline test runs
- ground-truth extraction comparison against `crane export`

## Limitations

- Docker Hub and Amazon ECR Public are supported. Arbitrary private registries
  are not yet supported.
- Device and FIFO entries are skipped because creating them requires elevated
  privileges and they are not useful for ordinary filesystem inspection.
- `dockertriage` extracts files. It is not a container runtime and does not run
  images.
- Filtered extraction can intentionally omit files outside the selected path.
  The coverage report tells you what was outside the filter.

## Development

```bash
git clone https://github.com/m1r3dk/dockertriage.git
cd dockertriage
uv sync
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md).

## Release readiness

Before changing repository visibility or publishing a release, run:

```bash
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy
uv run pytest -q
uv run python -m build
```

Then confirm the latest GitHub Actions run is green.

## License

[MIT](LICENSE)
