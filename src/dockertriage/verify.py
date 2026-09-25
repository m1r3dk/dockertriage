"""Prove that what was pulled is actually on disk, and complete.

A batch of 500 images scrolls past faster than anyone reads it, and the
interesting failures are the quiet ones: an interrupted run that left a
half-extracted tree, a disk that filled at image 380, a folder that was
copied to another machine and lost files on the way. Scrollback cannot
answer "did all of them land?", so every pull leaves a signed-off record in
`.image.json` and this module checks reality against it.

The record is written last and atomically, so its presence means the pull
reached the end. `rootfs` in it is a census of the tree taken immediately
after extraction, which is what makes a later count meaningful.
"""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Iterable
from typing import Any

from .constants import IMAGE_META_NAME, LAYER_CACHE_NAME
from .reference import parse_image

__all__ = [
    "CHECK_HELP",
    "Check",
    "TreeStats",
    "VerifyResult",
    "read_record",
    "scan_tree",
    "verify_dest",
    "verify_list",
    "verify_output_dir",
]

# Bookkeeping we wrote ourselves; it is not part of the image's filesystem.
_TOP_LEVEL_SKIP = {IMAGE_META_NAME, LAYER_CACHE_NAME}


@dataclasses.dataclass
class TreeStats:
    """A census of an extracted rootfs, comparable across time and machines."""

    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    bytes: int = 0
    unreadable: int = 0

    def as_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)

    def __str__(self) -> str:
        return f"{self.files} files, {self.dirs} dirs, {self.symlinks} symlinks, {self.bytes} bytes"


def scan_tree(root: str) -> TreeStats:
    """Count what is really on disk under `root`.

    Deliberately iterative rather than `os.walk`: walk classifies a symlink
    to a directory as a directory, which would make a rootfs full of
    symlinked dirs compare unequal to itself. Symlinks are never followed,
    so a link pointing outside the tree cannot inflate the count.
    """
    stats = TreeStats()
    stack = [(root, True)]
    while stack:
        current, is_root = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            stats.unreadable += 1
            continue
        for entry in entries:
            if is_root and entry.name in _TOP_LEVEL_SKIP:
                continue
            try:
                if entry.is_symlink():
                    stats.symlinks += 1
                elif entry.is_dir(follow_symlinks=False):
                    stats.dirs += 1
                    stack.append((entry.path, False))
                elif entry.is_file(follow_symlinks=False):
                    stats.files += 1
                    stats.bytes += entry.stat(follow_symlinks=False).st_size
                else:
                    # Sockets and the like: counted as present, not as files.
                    stats.unreadable += 1
            except OSError:
                stats.unreadable += 1
    return stats


def read_record(dest: str) -> dict[str, Any] | None:
    """Return the `.image.json` a completed pull leaves behind, if it is sound."""
    path = os.path.join(dest, IMAGE_META_NAME)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclasses.dataclass
class Check:
    """One named thing that was actually looked at, and what it found.

    Verification that cannot say what it did is indistinguishable from a
    verification that did nothing, so every step records itself here even
    when it passes.
    """

    name: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"check": self.name, "passed": self.passed}
        if self.detail:
            d["detail"] = self.detail
        return d

    def __str__(self) -> str:
        mark = "ok  " if self.passed else "FAIL"
        return f"{mark} {self.name}" + (f": {self.detail}" if self.detail else "")


# What each check actually inspects, printed once as a legend rather than
# repeated on every line. Kept here so the CLI never invents its own wording.
CHECK_HELP = {
    "folder exists": "the extracted directory is on disk",
    "record readable": f"{IMAGE_META_NAME} parses as JSON",
    "pull completed": "the record is marked complete, written only after the last layer",
    "layers recorded": "the record names the layers that were pulled",
    "not empty": "the folder holds something besides our own metadata",
    "file count": "files on disk vs files recorded at extraction",
    "dir count": "directories on disk vs directories recorded",
    "symlink count": "symlinks on disk vs symlinks recorded",
    "byte count": "total bytes on disk vs bytes recorded",
}


@dataclasses.dataclass
class VerifyResult:
    """One image's answer to "did this actually download?".

    `status` is the machine-readable reason, so a report can be filtered:
    ok, missing, incomplete, mismatch. `checks` is the audit trail: what was
    inspected, in order, and what each one found.
    """

    image: str
    dest: str
    status: str = "ok"
    problems: list[str] = dataclasses.field(default_factory=list)
    expected: dict[str, int] | None = None
    found: dict[str, int] | None = None
    checks: list[Check] = dataclasses.field(default_factory=list)
    depth: str = "quick"

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def record(self, name: str, passed: bool, detail: str = "") -> Check:
        check = Check(name=name, passed=passed, detail=detail)
        self.checks.append(check)
        if not passed:
            self.problems.append(f"{name}: {detail}" if detail else name)
        return check

    def summary(self) -> str:
        """One line naming how many checks ran and how they are counted."""
        passed = sum(1 for c in self.checks if c.passed)
        return f"{passed}/{len(self.checks)} checks passed ({self.depth})"

    def explain(self, width: int = 17) -> list[str]:
        """One aligned line per check: what was looked at, and what it found.

        The detail is the evidence (`335 == 335`), not a restatement of the
        check's name, so the lines stay short enough to read down a column.
        Square brackets are avoided because the CLI renders these through
        rich, which would eat `[like this]` as a markup tag.
        """
        lines = []
        for check in self.checks:
            mark = "ok  " if check.passed else "FAIL"
            detail = check.detail or CHECK_HELP.get(check.name, "")
            lines.append(f"{mark} {check.name:<{width}} {detail}".rstrip())
        return lines

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"image": self.image, "dest": self.dest, "ok": self.ok}
        d["status"] = self.status
        d["depth"] = self.depth
        d["checks"] = [c.as_dict() for c in self.checks]
        if self.problems:
            d["problems"] = list(self.problems)
        if self.expected is not None:
            d["expected"] = self.expected
        if self.found is not None:
            d["found"] = self.found
        return d

    def __str__(self) -> str:
        if self.ok:
            return f"ok {self.image}"
        return f"{self.status.upper()} {self.image}: {'; '.join(self.problems)}"


def verify_dest(dest: str, image: str | None = None, quick: bool = False) -> VerifyResult:
    """Check one extracted folder against the record the pull wrote.

    `quick` stops after the record: it answers "did the pull finish?" without
    touching the tree, which is what a batch wants right after pulling. The
    full check re-counts the tree, which is what catches a truncated copy or
    a disk that filled after the fact.

    Every step appends to `result.checks`, so the caller can show what was
    inspected rather than asking the user to take "verified" on faith.
    """
    dest = os.path.abspath(dest)
    name = image or os.path.basename(dest.rstrip(os.sep))
    result = VerifyResult(image=name, dest=dest, depth="quick" if quick else "deep")

    if not os.path.isdir(dest):
        result.status = "missing"
        result.record("folder exists", False, "no extracted folder")
        return result
    # The folder name, not the absolute path: the path is already printed
    # by the pull, and repeating it here just wraps the line.
    result.record("folder exists", True, os.path.basename(dest.rstrip(os.sep)))

    record = read_record(dest)
    if record is None:
        result.status = "incomplete"
        result.record(
            "record readable",
            False,
            f"no readable {IMAGE_META_NAME}: the pull never finished, "
            "or the folder was written by something else",
        )
        return result
    result.record("record readable", True, IMAGE_META_NAME)

    if not record.get("complete"):
        result.status = "incomplete"
        result.record("pull completed", False, f"{IMAGE_META_NAME} is not marked complete")
        return result
    result.record("pull completed", True, "record marked complete after the last layer")

    if image is None and record.get("image"):
        result.image = str(record["image"])
    layer_list = record.get("layers")
    if not layer_list:
        result.status = "incomplete"
        result.record("layers recorded", False, "record lists no layers")
        return result
    result.record("layers recorded", True, f"{len(layer_list)} layers")

    expected_raw = record.get("rootfs")
    expected = expected_raw if isinstance(expected_raw, dict) else None
    if expected:
        result.expected = {
            k: int(v) for k, v in expected.items() if isinstance(v, (int, float)) and k != "bytes"
        }
        result.expected["bytes"] = int(expected.get("bytes") or 0)

    if quick:
        # Even the quick path refuses to call an empty folder a success.
        if expected and int(expected.get("files") or 0) > 0:
            try:
                if not any(e.name not in _TOP_LEVEL_SKIP for e in os.scandir(dest)):
                    result.status = "mismatch"
                    result.record(
                        "not empty", False, "record expects files but the folder is empty"
                    )
                else:
                    result.record(
                        "not empty", True, f"{int(expected.get('files') or 0)} files expected"
                    )
            except OSError as exc:
                result.status = "missing"
                result.record("not empty", False, f"cannot read folder: {exc}")
        return result

    found = scan_tree(dest)
    result.found = found.as_dict()
    if expected is None:
        # Pulled by an older version that did not take a census. The folder
        # is complete, but there is nothing to compare it against.
        if found.files == 0 and found.symlinks == 0:
            result.status = "mismatch"
            result.record("not empty", False, "extracted folder holds no files")
        else:
            result.record("not empty", True, f"{found.files} files, {found.symlinks} symlinks")
        result.problems.append("record predates rootfs counts; nothing to compare")
        return result

    for field, label in (
        ("files", "file count"),
        ("dirs", "dir count"),
        ("symlinks", "symlink count"),
        ("bytes", "byte count"),
    ):
        want = int(expected.get(field) or 0)
        got = int(getattr(found, field))
        if want == got:
            result.record(label, True, f"{got} == {want}")
        else:
            result.status = "mismatch"
            result.record(label, False, f"recorded {want}, found {got}")
    if found.unreadable:
        result.problems.append(f"{found.unreadable} entries could not be read")
    return result


def verify_list(
    images: Iterable[str], out_dir: str, quick: bool = False, on_result=None
) -> list[VerifyResult]:
    """Verify every image in a list against the folders a batch would create.

    This is the direct answer to "did all of them download?": it starts from
    the list you asked for, not from the folders that happen to exist, so an
    image that was never attempted shows up as missing instead of silently
    not being counted.
    """
    results: list[VerifyResult] = []
    for raw in images:
        ref = raw.strip()
        if not ref:
            continue
        try:
            folder = parse_image(ref).folder_name
        except ValueError as exc:
            res = VerifyResult(image=ref, dest="", status="missing", problems=[str(exc)])
            results.append(res)
            if on_result is not None:
                on_result(res)
            continue
        res = verify_dest(os.path.join(out_dir, folder), image=ref, quick=quick)
        results.append(res)
        if on_result is not None:
            on_result(res)
    return results


def verify_output_dir(out_dir: str, quick: bool = False, on_result=None) -> list[VerifyResult]:
    """Verify every extracted folder found under `out_dir`.

    Used when the list that produced the folders is gone, or when the folder
    itself is the thing being handed to someone else.
    """
    results: list[VerifyResult] = []
    if not os.path.isdir(out_dir):
        raise OSError(f"not a directory: {out_dir}")
    # A single extracted rootfs is a valid argument too, not just a parent.
    if read_record(out_dir) is not None:
        res = verify_dest(out_dir, quick=quick)
        if on_result is not None:
            on_result(res)
        return [res]
    for name in sorted(os.listdir(out_dir)):
        # Skip our own bookkeeping and anything hidden: with --keep-tar a
        # failed pull can leave a bare `.layers/` behind, and reporting that
        # as a broken image would be noise, not a finding.
        if name.startswith("."):
            continue
        path = os.path.join(out_dir, name)
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        res = verify_dest(path, quick=quick)
        results.append(res)
        if on_result is not None:
            on_result(res)
    return results
