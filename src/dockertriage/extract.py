"""Apply layer tars to disk with overlayfs semantics.

This is where naive implementations lose symlinks and hardlinks. Link
targets may appear later in the same tar, so links are replayed after the
walk, and every path is confined to the rootfs before it is touched.
"""

import dataclasses
import errno
import os
import posixpath
import shutil
import tarfile
from typing import BinaryIO

from .constants import CHUNK

__all__ = [
    "ExtractStats",
    "apply_whiteout",
    "extract_layer",
    "open_layer_stream",
    "safe_join",
    "safe_relpath",
]


def safe_relpath(name: str) -> str | None:
    if not name:
        return None
    name = name.replace("\\", "/").lstrip("/")
    name = posixpath.normpath(name)
    if name in ("", ".") or name == ".." or name.startswith("../"):
        return None
    return name


def safe_join(root: str, rel_posix: str) -> str:
    dst = os.path.normpath(os.path.join(root, rel_posix.replace("/", os.sep)))
    root_norm = os.path.normpath(root)
    if dst != root_norm and not dst.startswith(root_norm + os.sep):
        raise ValueError(f"path traversal blocked: {rel_posix}")
    return dst


def _force_remove(path: str) -> None:
    try:
        if os.path.islink(path) or os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except FileNotFoundError:
        pass
    except OSError:
        shutil.rmtree(path, ignore_errors=True)


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(path)
    if not parent:
        return
    if os.path.islink(parent) or (os.path.exists(parent) and not os.path.isdir(parent)):
        # A previous layer left a file/symlink where this layer wants a dir.
        _force_remove(parent)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    if not os.access(parent, os.W_OK | os.X_OK):
        # An earlier layer may have set a read-only mode (e.g. 0555) on this
        # directory. Loosen it now; final modes are restored after the pull.
        try:
            os.chmod(parent, os.stat(parent).st_mode | 0o700)
        except OSError:
            pass


def apply_whiteout(rootfs: str, rel_posix: str) -> None:
    base = posixpath.basename(rel_posix)
    parent = posixpath.dirname(rel_posix)

    if base == ".wh..wh..opq":
        # Opaque marker: wipe the directory's inherited contents.
        target_dir = safe_join(rootfs, parent) if parent not in ("", ".") else rootfs
        if os.path.isdir(target_dir) and not os.path.islink(target_dir):
            for name in os.listdir(target_dir):
                _force_remove(os.path.join(target_dir, name))
        return

    if base.startswith(".wh."):
        removed = posixpath.join(parent, base[len(".wh.") :]) if parent else base[len(".wh.") :]
        _force_remove(safe_join(rootfs, removed))


@dataclasses.dataclass
class ExtractStats:
    """Counts per extraction run. dataclass gives us asdict() and repr for free."""

    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    hardlinks: int = 0
    whiteouts: int = 0
    skipped: int = 0

    def as_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)

    def __str__(self) -> str:
        return (
            f"{self.files} files, {self.dirs} dirs, {self.symlinks} symlinks, "
            f"{self.hardlinks} hardlinks, {self.whiteouts} whiteouts"
        )


def extract_layer(
    fileobj: BinaryIO, rootfs: str, stats: ExtractStats, preserve_mode: bool = True
) -> None:
    """Apply one layer tar onto rootfs, honouring overlayfs whiteout rules."""
    deferred_links: list[tarfile.TarInfo] = []
    deferred_dir_modes: list[tuple[str, int]] = []

    with tarfile.open(fileobj=fileobj, mode="r|*") as tf:
        for member in tf:
            rel = safe_relpath(member.name)
            if rel is None:
                stats.skipped += 1
                continue

            base = posixpath.basename(rel)
            if base.startswith(".wh."):
                try:
                    apply_whiteout(rootfs, rel)
                    stats.whiteouts += 1
                except ValueError:
                    stats.skipped += 1
                continue

            try:
                dst = safe_join(rootfs, rel)
            except ValueError:
                stats.skipped += 1
                continue

            if member.isdev() or member.isfifo():
                stats.skipped += 1
                continue

            if member.isdir():
                if os.path.islink(dst) or (os.path.exists(dst) and not os.path.isdir(dst)):
                    _force_remove(dst)
                os.makedirs(dst, mode=0o755, exist_ok=True)
                if preserve_mode:
                    deferred_dir_modes.append((dst, member.mode & 0o7777))
                stats.dirs += 1
                continue

            if member.issym() or member.islnk():
                # Link targets may appear later in the same tar, so replay at the end.
                deferred_links.append(member)
                continue

            if member.isreg():
                _ensure_parent(dst)
                _force_remove(dst)
                src = tf.extractfile(member)
                if src is None:
                    stats.skipped += 1
                    continue
                # Writable by owner so the output folder stays usable and deletable.
                mode = (member.mode & 0o7777) | 0o600 if preserve_mode else 0o644
                fd = os.open(dst, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
                with os.fdopen(fd, "wb") as out:
                    shutil.copyfileobj(src, out, CHUNK)
                src.close()
                stats.files += 1
                continue

            stats.skipped += 1

    for member in deferred_links:
        rel = safe_relpath(member.name)
        if rel is None:
            stats.skipped += 1
            continue
        try:
            dst = safe_join(rootfs, rel)
        except ValueError:
            stats.skipped += 1
            continue
        _ensure_parent(dst)
        _force_remove(dst)

        if member.issym():
            try:
                os.symlink(member.linkname, dst)
                stats.symlinks += 1
            except OSError:
                stats.skipped += 1
            continue

        # Hard link: resolve against the rootfs; copy if the source is gone.
        link_rel = safe_relpath(member.linkname)
        if link_rel is None:
            stats.skipped += 1
            continue
        try:
            src_path = safe_join(rootfs, link_rel)
        except ValueError:
            stats.skipped += 1
            continue
        try:
            os.link(src_path, dst)
            stats.hardlinks += 1
        except OSError as exc:
            if exc.errno in (errno.EXDEV, errno.EPERM, errno.ENOENT) and os.path.exists(src_path):
                try:
                    shutil.copy2(src_path, dst)
                    stats.hardlinks += 1
                    continue
                except OSError:
                    pass
            stats.skipped += 1

    # Directory permissions go on last: tightening them earlier would block
    # our own writes into those directories.
    for path, mode in reversed(deferred_dir_modes):
        try:
            os.chmod(path, mode | 0o700)
        except OSError:
            pass


def open_layer_stream(path: str, media_type: str) -> BinaryIO:
    """Return a readable stream for a layer blob, transparently decompressing."""
    mt = (media_type or "").lower()
    if "zstd" in mt:
        # zstd is decompressed by the standard library on Python 3.14+, which
        # is the minimum this package supports, so no third-party package or
        # fallback is needed.
        from compression import zstd

        return zstd.ZstdFile(path, "rb")  # type: ignore[return-value]
    # tarfile's 'r|*' handles gzip/bz2/xz and uncompressed transparently.
    return open(path, "rb")
