# srctriage

[![CI](https://github.com/m1r3dk/srctriage/actions/workflows/ci.yml/badge.svg)](https://github.com/m1r3dk/srctriage/actions/workflows/ci.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Download container images and GitHub repositories to disk, then triage them:
verify what landed and pull every credential out into one report.

**No Docker daemon. No root access. No running containers. No git needed.**

```bash
st alpine:3.19                       # an image's merged root filesystem
st github.com/octocat/Hello-World    # a repository's working tree
st secrets                           # every credential in what you pulled
```

## About

`srctriage` is a small Python CLI for people who need the files inside a
container image or a GitHub repository, not a running container or a dev
checkout. For an image it resolves manifests, downloads layers, verifies layer
digests, applies OCI whiteouts in order, preserves file modes, symlinks and
hardlinks, then writes a normal directory you can inspect with standard tools.
For a repository it downloads the tree at a branch, tag or commit as a single
archive, and optionally the full git history.

It is useful for:

- security triage and offline review of images and repositories
- finding leaked credentials, including ones deleted from git history
- source and application file extraction from container images
- batch collection from lists that mix images and repositories
- checking whether images or repositories are private, deleted, or missing
- producing repeatable JSON evidence for automation and audits
- inspecting image layers without installing Docker

Unlike `docker save`, the output is not a stack of layer tarballs. It is the
final merged filesystem the container would see after all layers are applied.

## Features

- Pulls images from Docker Hub and Amazon ECR Public
- Downloads GitHub repositories, public or private, at any branch, tag or commit
- Accepts tags, digests, registry references, Docker Hub URLs, and GitHub URLs
- Extracts a complete merged rootfs without Docker
- Downloads layers concurrently and extracts them in layer order
- Verifies every blob against the manifest SHA-256 digest
- Handles OCI whiteouts, opaque directories, hardlinks, symlinks, and read-only directories
- Lets you extract only a path with `--path`, or an image's `WorkingDir` with `--app`
- Reports what filtered extraction kept and what it left outside the filter
- Supports batch pulls from mixed image and repository lists with JSON reports
- Includes `st verify` for quick or deep checks after extraction
- Includes `st secrets`, which merges betterleaks, gitleaks and TruffleHog with
  name-based detection, and scans git history with `--history`
- Keeps the importable library stdlib-only, with Typer/Rich used only by the CLI

## Installation

### Recommended: pipx

```bash
pipx install "srctriage @ git+https://github.com/m1r3dk/srctriage.git"
```

Run once without installing:

```bash
pipx run --spec "srctriage @ git+https://github.com/m1r3dk/srctriage.git" st alpine:3.19
```

Install from a local checkout:

```bash
git clone https://github.com/m1r3dk/srctriage.git
pipx install ./srctriage
```

Upgrade or remove:

```bash
pipx upgrade srctriage
pipx uninstall srctriage
```

### pip

```bash
python -m pip install "srctriage @ git+https://github.com/m1r3dk/srctriage.git"
```

Or from a local checkout:

```bash
git clone https://github.com/m1r3dk/srctriage.git
cd srctriage
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
st alpine:3.19
```

`pull` is implied. This is equivalent:

```bash
st pull alpine:3.19
```

Choose a parent output directory or an exact destination:

```bash
st python:3.12-slim -o ./rootfs
st redis:7 -d ./redis-rootfs
```

Select another platform:

```bash
st nginx:latest --platform linux/arm64
```

Inspect layers without downloading them:

```bash
st inspect python:3.12-slim
```

Print only layer digests for scripts:

```bash
st inspect --digests alpine:3.19
```

Verify extracted images later:

```bash
st verify ./output
```

## GitHub repositories

A GitHub reference works anywhere an image reference does:

```bash
st github.com/pallets/flask                    # default branch
st github.com/pallets/flask@3.0.0              # a tag, branch or commit sha
st https://github.com/pallets/flask/tree/3.0.0 # a URL copied from the browser
st gh:pallets/flask -P src/flask               # only one folder
st git@github.com:pallets/flask.git            # a clone URL
```

The tree arrives as one archive, so no git is needed and the download is a
single request. The folder is named `github_<owner>_<repo>[_<ref>]` and carries
the same `.image.json` record as an image, including the exact commit sha that
was downloaded, so `st verify` and `st secrets` treat it like any other target.

Add `--history` (`-H`) to keep the full git history beside the tree in
`.history.git`. That needs git installed, and it is what lets `st secrets` find
credentials that were committed and later deleted:

```bash
st gh:trufflesecurity/test_keys --history
st secrets github_trufflesecurity_test_keys
```

```text
critical AKIAYVP4CIPPERUVIFXG
         keys:4 @ fbc14303ffbf  aws-access-token
```

`@ fbc14303ffbf` is the commit that introduced it: that key is no longer in
the tree, only in history.

Look at a repository without downloading it:

```bash
st inspect github.com/pallets/flask        # description, size, default branch
st inspect --digests gh:pallets/flask@main # the commit sha, for scripts
```

Public repositories need no credentials. For private repositories, or to raise
GitHub's API limits, set a token:

```bash
export GITHUB_TOKEN="$(gh auth token)"   # or GH_TOKEN
```

The token is sent only to `api.github.com` and to git, never to the download
host GitHub redirects to.

## What the output looks like

`st inspect` shows the resolved image, platform, compressed layer sizes, and the
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

`st pull` uses the same layer row format while downloading and extracting:

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
ROOTFS=$(st alpine:3.19 -q)
grep -R "example" "$ROOTFS"
```

## Extract only application files

Most container images contain a base OS, package manager files, shared
libraries, certificates, and runtime dependencies. If you only want application
files, filter the extraction.

```bash
st pull myorg/api:latest --path /app
st pull myorg/api:latest --app
st pull myorg/api:latest -P /app -P /etc/nginx
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

Use `st inspect` before pulling when you are not sure where the app lives. Look
for `COPY`, `ADD`, and `workdir` lines.

## Why extracted images have many symlinks

Docker images are Linux root filesystems. Symlinks are normal and expected.
Examples include:

- `/bin/sh -> busybox`
- `/usr/bin/python -> python3`
- shared library links under `/lib` and `/usr/lib`
- package-manager shortcuts
- `node_modules/.bin/*` links to package executables

`srctriage` preserves symlinks instead of flattening them because resolving
or copying targets would change what the container sees at runtime. If you only
care about source code, use `--app` or `--path` and read the filter report for
links that point outside the kept paths.

## Batch downloads

Create a list. Images and repositories can be mixed:

```text
# images.txt
alpine:3.19
redis:7
python:3.12-slim
https://hub.docker.com/_/nginx
public.ecr.aws/docker/library/ubuntu:24.04
github.com/pallets/flask@3.0.0
gh:octocat/Hello-World
```

Pull everything in the list:

```bash
st -f images.txt
```

Batch output defaults to `./output/`. Use options to tune concurrency and write
a report:

```bash
st -f images.txt -o ./rootfs -c 4 -j 8 -r pull-report.json
```

- `-c 4` pulls up to four images or repositories at once
- `-j 8` downloads up to eight layers per image
- `-r` writes JSON totals and per-reference results
- `-H` also keeps git history for every repository in the list

Blank lines, comments, duplicate entries, stray quotes, and trailing commas are
handled automatically.

Before downloading a batch, every reference is checked for accessibility.
Private, deleted, taken-down, or missing tags and refs are skipped and listed in
`output/not-downloaded.txt`, which can be fed straight back to `st -f`.

Disable that preflight with `--no-check-access` or `-N`.

## Finding secrets

`st secrets` collects every credential in what you pulled into one folder:

```bash
st -f images.txt          # pull into ./output
st secrets                # scan ./output, write ./extracted_secrets
st secrets ./output/github_pallets_flask -o ./flask-secrets
```

It runs whichever of [betterleaks](https://github.com/betterleaks/betterleaks),
gitleaks and TruffleHog are installed (`st secrets --list-engines` shows which),
then adds what they were measured to miss: values under secret-named variables
(`DB_PASSWORD=hunter2`), credential files by name (`.npmrc`, `.aws/credentials`,
private keys), and an image's baked-in `ENV`. For a repository pulled with
`--history`, every engine also reads every commit on every branch.

Values are written **in plaintext** so they can be rotated, so treat the output
folder as the credentials themselves. `UNSCANNED.md` lists everything nothing
looked at, because an engine that is not installed reports nothing, which
looks identical to finding nothing. `--fail-on-findings` exits 1 for CI gates.

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
st verify ./output
```

Include the original list to catch references that never created an output folder:

```bash
st verify ./output -f images.txt
```

Use `--deep` to walk the extracted tree and compare file, directory, symlink,
and byte counts against the census recorded at extraction time:

```bash
st verify ./output --deep
```

Deep verification detects changed aggregate counts. It does not hash every
extracted file, so a same-size content replacement is outside its scope.

## Command reference

| Command | Purpose |
| --- | --- |
| `st IMAGE` | Pull and extract one image. `pull` is implied. |
| `st github.com/OWNER/REPO[@REF]` | Download one repository's tree. |
| `st gh:OWNER/REPO --history` | Also keep full git history for `st secrets`. |
| `st pull IMAGE` | Explicit single-image pull. |
| `st pull REF --path P` | Extract only path `P` and report coverage. |
| `st pull IMAGE --app` | Extract only the image's `WorkingDir`. |
| `st -f FILE` | Preflight, pull, and verify a list of images and repositories. |
| `st verify PATH` | Verify previous downloads. |
| `st inspect IMAGE` | Show layer sizes and build commands without downloading layers. |
| `st inspect --digests IMAGE` | Print layer digests, one per line. |
| `st inspect REPO` | Show a repository's details without downloading it. |
| `st secrets [PATH]` | Extract every credential into a report folder. |
| `st --help` | Show top-level help. |
| `st COMMAND --help` | Show command help. |

Run `st pull --help`, `st inspect --help`, `st verify --help`, or
`st secrets --help` for the full option list.

## Credentials and rate limits

Anonymous Docker Hub pulls are rate-limited. Set Docker Hub credentials to raise
the limit or access repositories your account can pull:

```bash
export DOCKERHUB_USERNAME="your-username"
export DOCKERHUB_TOKEN="your-personal-access-token"
st -f images.txt -c 4
```

For GitHub, set `GITHUB_TOKEN` or `GH_TOKEN`. Public repositories download
anonymously from `codeload.github.com`, which does not count against the REST
API's 60-requests-an-hour anonymous limit.

Credentials are read only from environment variables. They are not written to
reports or output metadata.

## Python API

```python
from srctriage import pull, verify_dest

rootfs = pull("alpine:3.19", "./output")
result = verify_dest(rootfs, image="alpine:3.19", quick=False)

if not result.ok:
    raise RuntimeError(result.problems)

tree = pull("github.com/pallets/flask@3.0.0", "./output", history=True)
```

The library modules use only the Python standard library. CLI dependencies are
loaded only by the CLI.

## Safety and correctness

The extractor handles OCI whiteouts, opaque directories, symlinks, hardlinks,
type transitions between layers, read-only directories, and BuildKit attestation
entries. Archive paths and link targets are confined to the destination, for
repository archives as well as image layers.

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
- GitHub is the only supported code host. GitLab and Bitbucket are not yet
  supported.
- A repository download is the tree only. Git LFS objects arrive as pointer
  files and submodules as empty folders, as in GitHub's own archives.
- `--history` needs the git binary; nothing else does.
- Device and FIFO entries are skipped because creating them requires elevated
  privileges and they are not useful for ordinary filesystem inspection.
- `srctriage` extracts files. It is not a container runtime and does not run
  images or repository code.
- Filtered extraction can intentionally omit files outside the selected path.
  The coverage report tells you what was outside the filter.

## Development

```bash
git clone https://github.com/m1r3dk/srctriage.git
cd srctriage
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
