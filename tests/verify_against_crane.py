#!/usr/bin/env python3
"""Verify an extracted rootfs against `crane export` ground truth.

`crane` produces an already-merged rootfs tar, which is exactly what we should
produce on disk. Comparing against it catches the failures that are invisible
to a smoke test: dropped symlinks, skipped hardlinks, unapplied whiteouts.

    python3 tests/verify_against_crane.py alpine:3.19 debian:bookworm-slim

Requires `crane` on PATH (brew install crane). Everything else is stdlib.
Exits non-zero if any image mismatches.
"""

import os
import posixpath
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import srctriage as dp

DEFAULT_IMAGES = ["alpine:3.19", "debian:bookworm-slim", "python:3.12-slim", "redis:latest"]


def entry_kind_from_tar(m: tarfile.TarInfo) -> str:
    if m.isdir():
        return "d"
    if m.issym():
        return "l:" + m.linkname
    if m.islnk():
        return "h"
    if m.isreg():
        return f"f:{m.size}"
    return "other"


def load_crane_tar(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with tarfile.open(path) as tf:
        for m in tf:
            name = posixpath.normpath(m.name.lstrip("./").lstrip("/"))
            if name in ("", "."):
                continue
            out[name] = entry_kind_from_tar(m)
    return out


def load_extracted(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if rel == ".image.json":
                continue
            if os.path.islink(p):
                out[rel] = "l:" + os.readlink(p)
            elif os.path.isdir(p):
                out[rel] = "d"
            elif os.path.isfile(p):
                out[rel] = f"f:{os.path.getsize(p)}"
            else:
                out[rel] = "other"
        # Never descend through a symlinked directory: that would double-count
        # entries and can loop.
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return out


def crane_export(image: str, dest_tar: str, platform: str) -> None:
    env = dict(os.environ)
    # crane otherwise tries docker-credential-desktop and dies without Docker.
    cfg = tempfile.mkdtemp(prefix="crane-cfg-")
    with open(os.path.join(cfg, "config.json"), "w") as fh:
        fh.write("{}")
    env["DOCKER_CONFIG"] = cfg
    subprocess.run(
        ["crane", "export", image, "--platform", platform, dest_tar],
        check=True,
        env=env,
        capture_output=True,
    )


def compare(image: str, platform: str, workdir: str) -> bool:
    safe = image.replace("/", "_").replace(":", "_")
    tar_path = os.path.join(workdir, f"{safe}.tar")

    crane_export(image, tar_path, platform)
    truth = load_crane_tar(tar_path)
    os.remove(tar_path)

    os_name, arch = platform.split("/", 1)
    dest = dp.pull(
        image,
        workdir,
        dest_override=os.path.join(workdir, safe),
        quiet=True,
        os_name=os_name,
        arch=arch,
    )
    ours = load_extracted(dest)
    shutil.rmtree(dest, ignore_errors=True)

    missing = sorted(set(truth) - set(ours))
    extra = sorted(set(ours) - set(truth))
    # crane materializes hardlinks as regular files, so 'h' entries are
    # expected to differ in representation, not in content.
    mismatch = [
        (k, truth[k], ours[k])
        for k in sorted(set(truth) & set(ours))
        if not truth[k].startswith("h") and truth[k] != ours[k]
    ]

    ok = not (missing or extra or mismatch)
    print(
        f"{image:26} entries={len(truth):6} missing={len(missing):4} "
        f"extra={len(extra):4} mismatch={len(mismatch):4}  {'PASS' if ok else 'FAIL'}"
    )
    for k in missing[:5]:
        print(f"    - {k} ({truth[k]})")
    for k in extra[:5]:
        print(f"    + {k} ({ours[k]})")
    for k, a, b in mismatch[:5]:
        print(f"    ~ {k}  crane={a}  ours={b}")
    return ok


def main(argv: list[str]) -> int:
    if not shutil.which("crane"):
        print("crane not found on PATH (brew install crane)", file=sys.stderr)
        return 2

    images = argv[1:] or DEFAULT_IMAGES
    platform = os.environ.get("VERIFY_PLATFORM", "linux/amd64")
    workdir = tempfile.mkdtemp(prefix="st-verify-")
    print(f"verifying {len(images)} image(s) against crane export ({platform})\n")
    try:
        results = [compare(img, platform, workdir) for img in images]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
