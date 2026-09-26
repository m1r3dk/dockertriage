# dockertriage

[![CI](https://github.com/m1r3dk/dockertriage/actions/workflows/ci.yml/badge.svg)](https://github.com/m1r3dk/dockertriage/actions/workflows/ci.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Pull Docker and OCI images directly from a registry and extract their merged
root filesystem to disk.

**No Docker daemon. No root privileges. Built for reliable batch triage.**

```bash
dt alpine:3.19 -o ./rootfs
```

`dockertriage` downloads the image manifest and layers, verifies every layer's
SHA-256 digest, applies OCI whiteouts in order, preserves links and file modes,
and confirms that the final root filesystem was written successfully.

## Why dockertriage?

Use it when you need the files inside an image, not a running container:

- inspect container images on systems without Docker
- download hundreds of images from a list
- identify private, deleted, taken-down, or missing images before downloading
- extract a correctly merged root filesystem for security analysis
- produce JSON reports for automation and audit trails
- verify completion metadata and compare the extracted tree with its recorded census

Unlike `docker save`, the output is not a collection of layer archives. It is
the final merged filesystem, with whiteouts, symlinks, hardlinks, and layer
replacement semantics applied.

Docker Hub and Amazon ECR Public are supported. References may use tags,
digests, registry paths, or web URLs. Multi-platform selection, parallel layer
downloads, JSON reports, rate-limit checks, and a Python API are included.

## Installation

### Install as a CLI tool with pipx (recommended)

`dockertriage` is a command-line tool, so pipx is the cleanest way to get the
`dt` and `dockertriage` commands on your PATH in an isolated environment:

```bash
pipx install "dockertriage @ git+https://github.com/m1r3dk/dockertriage.git"
```

From a local checkout:

```bash
git clone https://github.com/m1r3dk/dockertriage.git
pipx install ./dockertriage
```

Run it once without installing:

```bash
pipx run --spec "dockertriage @ git+https://github.com/m1r3dk/dockertriage.git" dt alpine:3.19
```

Upgrade or remove:

```bash
pipx upgrade dockertriage
pipx uninstall dockertriage
```

### Install with pip

```bash
python -m pip install "dockertriage @ git+https://github.com/m1r3dk/dockertriage.git"
```

Or install from a local checkout:

```bash
git clone https://github.com/m1r3dk/dockertriage.git
cd dockertriage
python -m pip install .
```

Requirements:

- Python 3.14 or newer
- no Docker installation
- no daemon or root access

zstd-compressed layers are handled by the standard-library `compression.zstd`
module, which ships with Python 3.14, so no extra install is needed.

## Quick start

Pull and extract one image:

```bash
dt alpine:3.19
```

The `pull` command is implied. The explicit form is equivalent:

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

Inspect an image without downloading its layers:

```bash
dt inspect python:3.12-slim
```

For scripting, print just the layer digests, one per line:

```bash
dt inspect --digests alpine:3.19
```

## Extracting only the application

A container image is mostly base OS. When you only want the application's own
files, filter the extraction by path:

```bash
dt pull myorg/api:latest --path /app          # keep only /app
dt pull myorg/api:latest --app                # keep the image's WorkingDir
dt pull myorg/api:latest -P /app -P /etc/nginx   # repeatable
```

Every layer is still downloaded and applied in order, so whiteouts and
overwrites land correctly. Only the files under the requested paths are
written to disk.

### Knowing that nothing was left behind

A filter that silently drops files is worse than no filter, so a filtered pull
reports what it did against the image's own build history:

```
  keeping only: /usr/share/grafana
  12565 files, 1354 dirs, 141 symlinks, 0 hardlinks, 0 whiteouts, 1697 filtered out
  kept usr/share/grafana from layer(s) 1, 2, 3, 4, 5, 6, 7, 8
  outside the filter: COPY -> ./conf (layer 5)
  outside the filter: COPY -> /run.sh (layer 11)
```

Every `COPY` and `ADD` in the image records the path it wrote to. Any
destination that falls outside the filter is listed, so the files a filter
excluded are named rather than lost quietly. A path that matched nothing is
called out as a warning, which catches a typo before it looks like an empty
application. The same summary is stored under `filter` in `.image.json`, and
`dt verify` repeats it so a partial tree is never mistaken for a broken one.

Use `dt inspect` first to see where an image keeps its files:

```
$ dt inspect wordpress:latest

library/wordpress
:latest
linux/amd64

  #     size            step
  1   28.4MB ██▌        BASE debian.sh --arch 'amd64' out/ 'trixie'
  3  112.4MB ██████████ RUN apt-get install -y --no-install-recommends ...
 22    2.4KB ▏          COPY --chown=www-data wp-config-docker.php /usr/src/wordpress/
 23    1.7KB ▏          COPY docker-entrypoint.sh /usr/local/bin/

24 layers  262.0MB compressed
entrypoint docker-entrypoint.sh
cmd        apache2-foreground
workdir    /var/www/html -> dt pull --app
```

The bar makes the heavy layers obvious, and the `COPY` lines show where the
build put its own content. That image is also a good example of why the
coverage report matters: its `WorkingDir` is `/var/www/html`, but the WordPress
source ships in `/usr/src/wordpress`, so `--app` alone would hand back an empty
folder and say so.

## Batch downloads

Create a file containing one image reference per line:

```text
# images.txt
alpine:3.19
redis:7
python:3.12-slim
https://hub.docker.com/_/nginx
public.ecr.aws/docker/library/ubuntu:24.04
```

Download the list:

```bash
dt -f images.txt
```

Batch output defaults to `./output/`. Use `-o` to change it:

```bash
dt -f images.txt -o ./rootfs -c 4 -j 8 -r pull-report.json
```

- `-c 4` downloads up to four images concurrently
- `-j 8` downloads up to eight layers per image concurrently
- `-r` writes JSON totals, per-image results, and an `unattempted` count if a
  run stops early

Blank lines, comments, duplicate entries, stray quotes, and trailing commas in
the input file are handled automatically.

### Accessibility preflight

Before a multi-image batch starts, `dockertriage` checks the complete list and
reports which references the registry will serve:

```text
checking access for 100 images (no pull budget used)...
  70/100 accessible, 30 not
    24 private, deleted, or taken down
    6 tags do not exist
```

Only the 70 accessible images are downloaded. The other 30 are recorded in:

```text
output/not-downloaded.txt
```

Each line contains the image and the reason it was skipped:

```text
private/example  # private/example is private, deleted, or taken down
alpine:no-such-tag  # library/alpine has no tag 'no-such-tag'
```

The file remains a valid input list and can be retried later:

```bash
dt -f output/not-downloaded.txt
```

Disable the preflight with `--no-check-access` or `-N`.

## How verification works

Verification is automatic on every pull. It has two independent stages.

### 1. Layer integrity verification

Each downloaded blob is streamed through SHA-256. Its calculated digest must
match the digest declared by the image manifest before extraction succeeds.
This is enabled by default with `--verify` and can be disabled with
`--no-verify`.

### 2. Extracted output verification

After the final layer is applied, `dockertriage` atomically writes
`.image.json` and checks that:

- the destination directory exists
- `.image.json` is valid JSON
- the pull is marked complete
- the extracted layers are recorded
- the root filesystem is not empty

A successful pull prints the evidence:

```text
verifying (quick):
  ok   folder exists     library_alpine_3.19
  ok   record readable   .image.json
  ok   pull completed    record marked complete after the last layer
  ok   layers recorded   1 layers
  ok   not empty         90 files expected
verified: 5/5 checks passed (quick)
```

Use `--deep` to walk the extracted tree and compare its file, directory,
symlink, and byte counts with the census recorded at extraction time:

```bash
dt alpine:3.19 --deep
dt verify ./output --deep
```

Deep verification detects changes that alter aggregate file, directory,
symlink, or byte counts. It does not hash every extracted file, so a same-size
content replacement is outside its scope.

### Verify a batch later

Verify every extracted directory currently present:

```bash
dt verify ./output
```

For a complete answer, include the original list. This also catches images that
never created an output directory:

```bash
dt verify ./output -f images.txt
```

Write a JSON report or create a retry list:

```bash
dt verify ./output -f images.txt -r verify-report.json
dt verify ./output -f images.txt -F -q > retry.txt
dt -f retry.txt
```

The command exits with status `1` if any requested image is missing,
incomplete, or mismatched.

## Command reference

| Command | Purpose |
|---|---|
| `dt IMAGE` | Pull and extract one image. `pull` is implied. |
| `dt pull IMAGE` | Explicit single-image pull. |
| `dt pull IMAGE --path P` | Extract only path `P`, with a coverage report. |
| `dt pull IMAGE --app` | Extract only the image's `WorkingDir`. |
| `dt -f FILE` | Preflight, pull, and verify an image list. |
| `dt verify PATH` | Verify previously extracted images. |
| `dt inspect IMAGE` | Display layer sizes and build commands without downloading layers. |
| `dt inspect --digests IMAGE` | Print layer digests, one per line, for scripting. |
| `dt --help` | Show all commands. |
| `dt COMMAND --help` | Show command-specific options. |

Run `dt pull --help` or `dt verify --help` for the full option reference.

## Docker Hub credentials and rate limits

Anonymous Docker Hub pulls are rate-limited. Batch mode checks the available
pull budget before downloading so a large run does not fail unexpectedly
halfway through.

Set Docker Hub credentials to raise the rate limit or access repositories your
account can pull:

```bash
export DOCKERHUB_USERNAME="your-username"
export DOCKERHUB_TOKEN="your-personal-access-token"
dt -f images.txt -c 4
```

Credentials are read only from environment variables. They are not written to
reports or output metadata.

## Output and automation

A batch creates one directory per successfully extracted image under
`./output/` by default. Each directory contains the merged root filesystem and
a `.image.json` record with the resolved reference, platform, image
configuration, layers, completion state, extraction statistics, and tree
census. Inaccessible references are listed in `output/not-downloaded.txt`.

The final destination path is written to standard output. Progress and
verification details are written to standard error, so command substitution
remains safe:

```bash
ROOTFS=$(dt alpine:3.19 -q)
grep -R "example" "$ROOTFS"
```

## Python API

```python
from dockertriage import pull, verify_dest

rootfs = pull("alpine:3.19", "./output")
result = verify_dest(rootfs, image="alpine:3.19", quick=False)

if not result.ok:
    raise RuntimeError(result.problems)
```

The library modules use the Python standard library. Typer and Rich are loaded
only by the command-line interface.

## Safety and correctness

The extractor handles OCI whiteouts, opaque directories, symlinks, hardlinks,
type transitions between layers, read-only directories, and BuildKit
attestation entries. Archive paths and link targets are confined to the
destination. CI runs on Python 3.14, runs the unit suite without
network access, checks packaging and types, and compares real extractions with
`crane export`.

## Limitations

- Docker Hub and Amazon ECR Public are supported. Arbitrary private registries
  are not yet supported.
- Device and FIFO entries are skipped because creating them requires elevated
  privileges and they are not useful for ordinary filesystem inspection.
- `dockertriage` extracts files. It is not a container runtime and does not run
  images.

## Development

```bash
git clone https://github.com/m1r3dk/dockertriage.git
cd dockertriage
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check src tests
uv run mypy
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines,
[SECURITY.md](SECURITY.md) for vulnerability reporting, and
[CHANGELOG.md](CHANGELOG.md) for release history.

## License

[MIT](LICENSE)
