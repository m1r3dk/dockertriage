# The original spec

This is the specification the tool was first built against. It is kept as a
design record because the constraints below are the actual product:
"download a Docker image" is easy, and doing it *correctly* is where every
naive implementation fails.

**This is history, not documentation.** It describes the original scope and
has not been extended as the tool grew, so it does not mention `dt verify`,
the pre-download access check, or anything else added later. For what the
tool does today, read [README.md](README.md); for the rules a change has to
respect, read [CONTRIBUTING.md](CONTRIBUTING.md).

---

Build a single-file Python CLI that downloads a Docker image and leaves a fully
extracted, merged root filesystem in a folder.

## Hard constraints

- Python 3.9+ standard library ONLY for the library modules. No requests, no
  docker SDK. `import dockertriage` must not pull in a third-party package.
- No docker daemon, no `docker pull`, no root privileges.
- Third-party imports are confined to `cli.py`, which uses Typer for the
  interface. CI fails if they leak anywhere else.

## Input / output

- Accept: `alpine`, `alpine:3.19`, `org/app:tag`, `repo@sha256:...`,
  `docker.io/...`, `public.ecr.aws/ns/repo`, and `https://hub.docker.com/r/org/app`
  and `https://hub.docker.com/_/redis` web URLs.
- Flags: `-o/--output` (parent dir), `-d/--dest` (exact dir), `-j/--jobs`
  (parallel downloads), `--os`, `--arch`, `--keep-tar`, `-q/--quiet`.
- Print the absolute destination path on stdout. Send progress to stderr so
  `DEST=$(tool alpine -q)` works in scripts.
- Write an `.image.json` into the output folder: image config (Env, Entrypoint,
  Cmd, WorkingDir, User), the layer list with each layer's Dockerfile command,
  and extraction counts.

## How it must work

1. Get an anonymous pull token from auth.docker.io (or public.ecr.aws).
2. Fetch the manifest. If it is a manifest list / OCI index, select the entry
   matching `--os`/`--arch`. IGNORE buildkit attestation entries, which have
   `platform.architecture == "unknown"`.
3. Fetch the config blob to recover per-layer Dockerfile commands. Config
   `history` includes metadata-only steps with `empty_layer: true` that have NO
   corresponding layer blob, so align the two lists rather than zipping naively.
4. Download ALL layers in parallel, but EXTRACT them strictly in order, so
   overlay semantics hold. Do not wait for all downloads before extracting:
   extract layer N as soon as it lands.
5. Resolve the manifest exactly once and reuse it. Do not re-resolve inside the
   extraction function.
6. Use keep-alive HTTPS connections, one per thread.
7. Blob requests redirect to a signed CDN URL. You MUST drop the registry
   `Authorization` header when following that redirect, or the CDN rejects it.

## Correctness requirements

These are where naive implementations break.

- **Symlinks** must be recreated with `os.symlink`, preserving the target
  verbatim, including absolute and dangling targets. Do not resolve or skip
  them. An alpine rootfs has ~335 symlinks; extracting 0 means `/bin/sh` does
  not exist.
- **Hardlinks** must be materialized with `os.link`, falling back to a file copy
  on EXDEV/EPERM. Do not skip them.
- Link targets may appear LATER in the same tar, so defer all link creation
  until the tar has been fully walked.
- **Whiteouts**: `.wh.<name>` deletes that entry, `.wh..wh..opq` clears a
  directory's inherited contents. Apply them, and never write a `.wh.` file into
  the output.
- **Type transitions** across layers: file replaced by dir, dir replaced by
  file, symlink replaced by regular file, and a parent symlink that a later
  layer needs to be a real directory. Remove the old entry first.
- **Path traversal**: reject `../` members and confine absolute paths to the
  destination root. Critically, if a member path passes through an existing
  SYMLINK pointing outside the root, replace the symlink rather than writing
  through it.
- A directory with mode `0555` from an earlier layer must not block writes from
  a later layer. Loosen it during extraction and apply final modes at the end.
- Extracted files must stay owner-writable, so the folder is usable and
  deletable. Do not write mode `0444`.
- Skip device and FIFO entries.
- Handle gzip, bzip2, xz and uncompressed layers transparently. For zstd, fail
  with a clear message unless Python 3.14+ `compression.zstd` is available.

## Verification

Do this. Do not just claim it works.

- Write offline unit tests using in-memory tars for every correctness bullet
  above: whiteouts, opaque dirs, hardlinks, deferred link targets, traversal,
  symlink-escape overwrite, type transitions, read-only dirs, platform
  selection. No network in the tests.
- Then verify against ground truth: run
  `crane export <image> --platform linux/amd64 out.tar` and diff it against the
  extracted tree, comparing the full set of paths, entry types, symlink targets
  and file sizes. Report missing / extra / mismatched counts. Do this for at
  least `alpine:3.19`, `debian:bookworm-slim`, `python:3.12-slim` and
  `redis:latest`. All must be zero.
- Benchmark and report wall-clock time per image.
- Confirm zero third-party imports by AST-scanning the file, and prove it by
  running under the system `python3` with no virtualenv.

Report the crane diff counts and timings as evidence.

---

## Notes on why this prompt is shaped this way

The verification block matters more than the feature list. "Downloads a Docker
image" looks correct while silently dropping every symlink, and a smoke test
will not catch it. Naming `crane export` as ground truth is what converts
"looks fine" into a 0-missing / 0-extra / 0-mismatch number.

Two requirements came from bugs found during implementation, not from foresight:
the read-only-directory rule, which a unit test caught, and the CDN
`Authorization` header rule, which fails only against real blob storage.
