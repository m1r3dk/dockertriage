# dockertriage

[![CI](https://github.com/lalkishan/dockertriage/actions/workflows/ci.yml/badge.svg)](https://github.com/lalkishan/dockertriage/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Download a Docker image and get its complete root filesystem in a folder.
The command is **`dt`**.

**No Docker daemon. No root.** The library itself is standard library only;
the `dt` command adds Typer for its interface.

```bash
dt python:3.12-slim -o ./out
```

```
library/python:3.12-slim -> 4 layers, 44.0MB compressed (resolved in 0.9s)
  [1/4] extract   28.4MB  # debian.sh --arch 'amd64' out/ 'trixie'
  [2/4] extract    4.1MB  RUN set -eux; apt-get update; apt-get install -y ...
  [3/4] extract   11.6MB  RUN set -eux; savedAptMark="$(apt-mark showmanual)" ...
  [4/4] extract     249B  RUN set -eux; for src in idle3 pip3 pydoc3 python3 ...
  4451 files, 715 dirs, 506 symlinks, 1 hardlinks, 0 whiteouts
done in 10.95s
./out/library_python_3.12-slim
```

## Why

`docker pull` needs a daemon. `docker save` gives you a tar of tars you still
have to merge yourself, applying whiteouts by hand. Most Python snippets that
claim to do this silently drop symlinks and hardlinks, so you get a rootfs
where `/bin/sh` does not exist.

This gives you the real merged filesystem, on disk, ready to grep.

## Install

```bash
pip install dockertriage
```

Python 3.9+. This installs Typer for the CLI. If you are embedding the library
rather than calling `dt`, `import dockertriage` touches nothing outside the
standard library, and CI enforces that.

### With uv

Run it without installing anything:

```bash
uvx --from dockertriage dt alpine:3.19
```

From a checkout, `uv run` builds the environment on first use:

```bash
uv run dt alpine:3.19            # the CLI
uv run python -m dockertriage --version
uv sync                          # adds pytest and ruff from the dev group
uv run pytest tests/
uv run ruff check src tests
```

### With pip

```bash
pip install -e .
python -m dockertriage alpine:3.19   # or just: dt alpine:3.19
```

### Commands

```bash
dt alpine:3.19 -o ./out        # 'pull' is implied
dt pull alpine:3.19 -o ./out   # or say it explicitly
dt verify ./out                # did everything actually download?
dt inspect python:3.12-slim    # layer table, downloads nothing
dt layers alpine:3.19          # digests, one per line
dt --install-completion
```

```
                       library/python:3.12-slim  (linux/amd64)
┏━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃   size ┃ command                                                         ┃
┡━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1 │ 28.4MB │ # debian.sh --arch 'amd64' out/ 'trixie' '@1787529600'          │
│ 2 │  4.1MB │ RUN /bin/sh -c set -eux; apt-get update; apt-get install -y --… │
│ 3 │ 11.6MB │ RUN /bin/sh -c set -eux; savedAptMark="$(apt-mark showmanual)"… │
│ 4 │   249B │ RUN /bin/sh -c set -eux; for src in idle3 pip3 pydoc3 python3 … │
└───┴────────┴─────────────────────────────────────────────────────────────────┘
4 layers, 44.0MB compressed   entrypoint=None  cmd=['python3']
```

**One CLI.** There used to be two, an argparse one and a Typer one, kept in
sync by hand. They drifted: batch mode worked in one and not the other, and
`dt layers` shipped raising `NameError` because nothing ran it. Typer is now
the only interface, and the flag surface is asserted in tests rather than
maintained by discipline.

## Usage

```bash
dt alpine:3.19                       # -> ./library_alpine_3.19
dt python:3.12-slim -o ./out         # parent dir for the folder
dt redis:7 -d /tmp/redis-rootfs      # exact destination folder
dt nginx --arch arm64                # other platforms
dt alpine@sha256:abc...              # pin by digest
dt https://hub.docker.com/r/org/app  # hub URLs work
dt public.ecr.aws/nginx/nginx        # public ECR works
dt alpine -j 16 --keep-tar           # more parallelism, keep blobs
```

### Many images at once

Put one reference per line in a file:

```
# images.txt
alpine:3.19
redis:7
https://hub.docker.com/r/org/app
public.ecr.aws/nginx/nginx
```

```bash
dt -f images.txt                # every image lands in ./output/
dt -f images.txt -o ./out       # or pick the parent directory
dt -f images.txt -c 4           # 4 images at a time
dt -f images.txt -r report.json # machine-readable outcome per image
dt -f - < images.txt            # or read stdin
```

With `--file`, the extracted folders go under `./output/` unless `-o` says
otherwise, so a list of 500 images never litters the working directory. A
single image still lands in the current directory.

The list tolerates blank lines, `#` comments, stray quotes and trailing commas,
and skips duplicates. A failing image never stops the run; the exit code is
non-zero if any image failed.

Two separate knobs control parallelism: `-c` is how many **images** download at
once, `-j` is how many **layers** within each image. `-c 4 -j 8` can hold 32
connections open.

### Which ones can even be downloaded?

A list of a few hundred Docker Hub references always contains some that are
private, deleted, or taken down. Batch mode asks the registry about the whole
list first, so those are a number you get up front rather than a slow drip of
failures between real progress:

```
checking access for 7 images (no pull budget used)...
  3/7 accessible, 4 not (1.7s)
    3 private, deleted, or taken down
    1 tag does not exist
```

Only the reachable ones are downloaded. The rest are never attempted, and the
names go in a file next to the output:

```
4 of 7 images were never downloadable and were skipped before downloading
  written to ./output/not-downloaded.txt
```

```
# Images that could not be downloaded, and why.
# Re-runnable with: dt -f this-file
someorg/web  # someorg/web is private, deleted, or taken down
someorg/api  # someorg/api is private, deleted, or taken down
alpine:no-such-tag-9912  # library/alpine has no tag 'no-such-tag-9912'
nope-xyz/not-real  # nope-xyz/not-real is private, deleted, or taken down
```

That file is a valid image list, so when the repos come back it feeds straight
back in with `dt -f output/not-downloaded.txt`.

In the summary table those images read `skip`, not `FAIL`, because nothing
went wrong with the download: there was never anything to download. The
report (`-r`) counts them separately as `skipped_inaccessible`, and every
image from your list appears in `results` either way, so the answer is never
shorter than the question.

| Status | Meaning |
|---|---|
| `inaccessible` | private, deleted, or taken down |
| `missing_tag` | the repository is public but has no such tag |
| `rate_limited` | the registry throttled us before it could be checked |
| `error` | the check itself failed, e.g. the network dropped |

**The check costs no pull budget.** It reads the access claim in the token
the registry hands out, then sends a HEAD for the manifest. Neither is a pull:
measured against Docker Hub's own counter, the remaining count does not move.
An unreachable repo costs a single request, since the token already settles it.

Measured on a 122-image list of real Docker Hub URLs:

```
105/122 accessible, 17 not, in 8.8s
quota consumed: 0
```

Every one of those verdicts was cross-checked against real manifest
resolution: 0 false negatives in the 17 rejected, 0 false positives in the
105 accepted.

A missing `latest` is deliberately *not* treated as unreachable. When you did
not type a tag, the pull falls back to the newest real one, so the preflight
agrees with it rather than rejecting images that download fine.

Turn it off with `-N` (`--no-check-access`); a single image skips it anyway,
since trying is just as fast as asking.

### Did they all actually download?

Every pull verifies itself and says what it checked. "Verified" with nothing
behind it is just a word, so the checks are named along with their evidence:

```
done in 3.52s (fetch+extract 1.67s)
verifying (quick):
  ok   folder exists     library_alpine_3.19
  ok   record readable   .image.json
  ok   pull completed    record marked complete after the last layer
  ok   layers recorded   1 layers
  ok   not empty         90 files expected
verified: 5/5 checks passed (quick)
```

`--deep` re-walks the tree and compares it against the census taken at
extraction, so the numbers themselves are the proof:

```
verifying (deep):
  ok   folder exists     library_alpine_3.19
  ok   record readable   .image.json
  ok   pull completed    record marked complete after the last layer
  ok   layers recorded   1 layers
  ok   file count        90 == 90
  ok   dir count         101 == 101
  ok   symlink count     335 == 335
  ok   byte count        7393371 == 7393371
verified: 8/8 checks passed (deep)
```

A batch states its method once, then carries the evidence on every line:

```
verifying each image (quick): folder exists, .image.json parses, pull marked
complete, layers recorded, folder not empty (use --deep to re-count every file)
[1/3] ok   busybox (3.4s)  5/5 checks passed (quick)
[2/3] ok   alpine:3.19 (3.6s)  5/5 checks passed (quick)
[3/3] FAIL nope-xyz/not-real (1.1s)  RuntimeError: access denied: nope-xyz/not-real is
              private, deleted, or needs login (HTTP 401)

2/3 ok, 1 failed in 4.5s
2/3 verified on disk
  each image: 5/5 checks passed (quick)
```

An image that pulls but leaves nothing readable behind is reported as a
failure, not a success, so the tally is a statement about disk rather than
about what the code believed it did.

#### What each check inspects

| Check | Inspects | When |
|---|---|---|
| `folder exists` | the extracted directory is on disk | always |
| `record readable` | `.image.json` parses as JSON | always |
| `pull completed` | the record is marked complete, written only after the last layer | always |
| `layers recorded` | the record names the layers that were pulled | always |
| `not empty` | the folder holds something besides our own metadata | quick |
| `file count` | files on disk vs files recorded at extraction | `--deep` |
| `dir count` | directories on disk vs directories recorded | `--deep` |
| `symlink count` | symlinks on disk vs symlinks recorded | `--deep` |
| `byte count` | total bytes on disk vs bytes recorded | `--deep` |

Quick is the default because it costs one small JSON read per image, so it can
run on every pull without slowing anything down. `--deep` walks every file.

#### Asking again later

The answer survives the terminal:

```bash
dt verify ./output                      # check every folder that is there
dt verify ./output -f images.txt        # check against the list you asked for
dt verify ./output --deep               # re-count every file, not just the marker
dt verify ./output -r verify.json       # machine-readable, including each check
```

Use `-f` when you want the honest answer. Without it, `verify` can only check
the folders that exist, so an image that never downloaded is invisible. With
it, that image is reported as **missing**.

A failure names the check that failed and both numbers:

```
                             2 images (deep check)
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃      ┃ image                  ┃ status   ┃ checks ┃ detail                   ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ FAIL │ library/alpine:3.19    │ mismatch │ 6/8    │ file count: recorded 90, │
│      │                        │          │        │ found 89; byte count:    │
│      │                        │          │        │ recorded 7393371, found  │
│      │                        │          │        │ 7393361                  │
│ ok   │ library/busybox:latest │ ok       │ 8/8    │ ./output/library_busybox │
└──────┴────────────────────────┴──────────┴────────┴──────────────────────────┘
checks performed per image:
  folder exists    the extracted directory is on disk
  record readable  .image.json parses as JSON
  pull completed   the record is marked complete, written only after the last layer
  layers recorded  the record names the layers that were pulled
  file count       files on disk vs files recorded at extraction
  dir count        directories on disk vs directories recorded
  symlink count    symlinks on disk vs symlinks recorded
  byte count       total bytes on disk vs bytes recorded
1/2 images verified
```

Failed images go to stdout, so retrying is a pipe:

```bash
dt verify ./output -f images.txt -F -q > retry.txt
dt -f retry.txt
```

Every pull ends by writing `.image.json` atomically, after the last layer is
extracted. Its presence is what proves the pull finished rather than being
killed halfway, and the `rootfs` census inside it is what `--deep` compares
against, which is how a folder that later lost files to a full disk or a
truncated copy gets caught. The exit code is 1 if anything failed to verify.

| Status | Meaning |
|---|---|
| `ok` | Complete, and the tree matches what was recorded. |
| `missing` | The folder is not there. The image never downloaded. |
| `incomplete` | Files exist but the pull never finished writing its record. |
| `mismatch` | The pull finished, but the tree has since changed. |

`-q` suppresses the explanation and leaves only the path on stdout, so
`$(dt alpine -q)` stays scriptable. `-X` turns the check off entirely.

### Rate limits

Docker Hub allows roughly **100 anonymous manifest pulls per 6 hours per IP**,
which a list of a few hundred images will exhaust.

Batch runs check the remaining budget before starting, so you learn the list is
too big up front rather than 90 images in:

```
docker hub: 12/100 pulls left per 6h (anonymous)
  122 images but only 12 pulls left: expect to stop around image 12
  set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN to raise the limit
```

The check uses a HEAD request against Docker's `ratelimitpreview` image, which
does not consume a pull. Skip it with `-b`.

Credentials raise the ceiling and unlock private repos:

```bash
export DOCKERHUB_USERNAME=you
export DOCKERHUB_TOKEN=dckr_pat_...   # Account Settings -> Personal access tokens
dt -f images.txt -c 4
```

Credentials are read from the environment only. Reading `~/.docker/config.json`
would mean invoking credential-helper binaries, which would break the promise
that this runs anywhere with nothing installed.

When the limit is hit, the batch stops rather than turning every remaining
image into an identical failure.

The absolute destination path goes to stdout and progress goes to stderr, so
this works cleanly in scripts:

```bash
ROOTFS=$(dt alpine:3.19 -q)
grep -r "AKIA" "$ROOTFS"
```

Each pull also writes `.image.json` alongside the rootfs, containing the image
config (Env, Entrypoint, Cmd, WorkingDir, User), every layer with the
Dockerfile command that produced it, extraction counts, and a census of the
extracted tree that `dt verify` checks against later.

## Correctness

Verified against `crane export`, comparing every path, entry type, symlink
target and file size. CI runs this on every push, so it is a gate rather
than a claim:

```
alpine:3.19                entries=  526 missing=0 extra=0 mismatch=0  PASS
debian:bookworm-slim       entries= 4225 missing=0 extra=0 mismatch=0  PASS
python:3.12-slim           entries= 5579 missing=0 extra=0 mismatch=0  PASS
redis:latest               entries= 3301 missing=0 extra=0 mismatch=0  PASS
```

Entry counts move when upstream rebuilds a tag; the number that matters is
that `missing`, `extra` and `mismatch` are all zero. Reproduce it yourself
with `python tests/verify_against_crane.py alpine:3.19` (needs `crane`).

Handled explicitly, because each one is a way naive extractors go wrong:

| Case | Why it matters |
|---|---|
| **Symlinks** | alpine has 335. Drop them and `/bin/sh` does not exist. |
| **Hardlinks** | Skipping them silently loses files from the tree. |
| **Deferred links** | A link's target can appear later in the same tar. |
| **Whiteouts** | `.wh.foo` deletes; `.wh..wh..opq` clears a directory. |
| **Type transitions** | Layers turn files into dirs, dirs into files, symlinks into files. |
| **Path traversal** | `../` members and symlinks pointing outside the root are confined. |
| **Read-only dirs** | A `0555` dir from layer 1 must not block layer 2's writes. |
| **Attestation entries** | buildkit adds `architecture: unknown` entries that are not images. |
| **File modes** | Output stays owner-writable, so the folder is usable and deletable. |
| **Silent partial runs** | A batch says how many images are verifiably on disk, not how many calls returned. |
| **Dead references** | Private, deleted and taken-down repos are found before downloading, not during. |

## Speed

One token, one manifest resolution, parallel layer downloads, and extraction
that starts as soon as layer 1 lands rather than after the last byte.

| Image | Time |
|---|---|
| alpine:3.19 | 3.1s |
| debian:bookworm-slim | 6.5s |
| python:3.12-slim | 7.3s |

These are wall-clock on one machine on one connection, and most of it is
download. Treat them as a rough shape rather than a benchmark: your numbers
will track your bandwidth to Docker's CDN more than anything in this code.

## Layout

```
src/dockertriage/
  reference.py   what the user typed -> a registry coordinate
  registry.py    auth, keep-alive connections, blob download
  manifest.py    platform selection, layer list, Dockerfile commands
  extract.py     tar -> disk, whiteouts, symlinks, hardlinks
  puller.py      pull one image end to end
  batch.py       pull many, isolating failures
  preflight.py   which references the registry will actually serve
  verify.py      prove what was pulled is on disk and complete
  ratelimit.py   Docker Hub pull budget
  cli.py         the Typer interface, and the only module with dependencies
```

`extract.py` is the module that matters. Everything above it is plumbing;
that file is where symlinks and hardlinks are either preserved or silently
lost. Only `cli.py` may import a third-party package, and CI fails the build
if anything else does, or if `import dockertriage` starts pulling in Typer.

## Tests

```bash
uv run pytest tests/                      # everything (213 tests)
python3 tests/test_dockertriage.py        # library modules, offline
python3 tests/test_cli.py                 # the CLI
python3 tests/verify_against_crane.py     # ground-truth diff (needs crane)
```

The unit tests build tar archives in memory and assert on the extracted tree,
so every correctness case above is pinned without touching the network.

## Troubleshooting

**`CERTIFICATE_VERIFY_FAILED` on every pull.** Your Python has no CA bundle,
which is common for a Homebrew or pyenv build and for a `python -m venv`
created from one. Nothing is wrong with the image or the network; the
interpreter cannot verify TLS at all. Fix the interpreter:

```bash
# macOS, python.org installer
/Applications/Python\ 3.12/Install\ Certificates.command

# Homebrew or any build missing a bundle: point OpenSSL at certifi
pip install certifi
export SSL_CERT_FILE="$(python -m certifi)"
```

Environments created by `uv venv` already carry a working bundle.

**`rate limited by registry-1.docker.io`.** Docker Hub allows roughly 100
anonymous pulls per 6 hours per IP. Set `DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN`, or wait for the window to reset. See
[Rate limits](#rate-limits).

**`access denied: <repo> is private, deleted, or needs login`.** The image is
genuinely unreachable anonymously. In a batch this is found before
downloading, and those names land in `output/not-downloaded.txt`.

**A layer needs zstd.** Install the extra: `pip install 'dockertriage[zstd]'`,
or run on Python 3.14+, which has `compression.zstd` built in.

## Limitations

- zstd layers need Python 3.14+ (`compression.zstd`) or the optional
  `zstandard` package. Gzip, bzip2, xz and uncompressed are native.
- Public images only. No private-registry credential flow yet.
- Device and FIFO entries are skipped: they need root and are not useful for
  filesystem inspection.

## License

MIT
