"""Pull one image and leave a merged rootfs on disk.

Layers download in parallel but extract strictly in order, so a later
layer's whiteouts always land on the base they were built against.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .constants import IMAGE_META_NAME, LAYER_CACHE_NAME
from .extract import ExtractStats, extract_layer, open_layer_stream
from .humanize import human_bytes, one_line
from .manifest import resolve_layers
from .reference import parse_image
from .registry import RegistryClient
from .verify import scan_tree

__all__ = ["pull"]


def pull(
    image_input: str,
    out_dir: str,
    jobs: int = 8,
    os_name: str = "linux",
    arch: str = "amd64",
    keep_tar: bool = False,
    quiet: bool = False,
    dest_override: str | None = None,
    verify: bool = True,
    strict_tag: bool = False,
) -> str:
    started = time.time()

    def log(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr, flush=True)

    image = parse_image(image_input)
    client = RegistryClient(image)
    try:
        t0 = time.time()
        layers, config = resolve_layers(client, os_name, arch, strict_tag)
        resolve_s = time.time() - t0
        total_bytes = sum(layer.size for layer in layers)
        if image.ref_inferred:
            log(f"  no 'latest' tag; using {image.ref}")
        log(
            f"{image.pretty} -> {len(layers)} layers, "
            f"{human_bytes(total_bytes)} compressed (resolved in {resolve_s:.2f}s)"
        )

        dest = os.path.abspath(dest_override or os.path.join(out_dir, image.folder_name))
        if os.path.exists(dest):
            shutil.rmtree(dest)
        os.makedirs(dest, exist_ok=True)

        cache_dir = (
            os.path.join(dest, LAYER_CACHE_NAME)
            if keep_tar
            else tempfile.mkdtemp(prefix="dockertriage-")
        )
        os.makedirs(cache_dir, exist_ok=True)

        blob_paths: list[str] = [
            os.path.join(cache_dir, f"{i:03d}_{layer.digest.split(':')[-1][:16]}.tar")
            for i, layer in enumerate(layers)
        ]

        progress_lock = threading.Lock()
        seen_bytes = [0]
        # True while a "\r downloading ..." line is on the terminal and needs a
        # newline before anything else prints. Without this we emit a blank line
        # after every already-downloaded layer, since progress is cumulative and
        # reaches 100% long before the last layer extracts.
        progress_open = [False]

        def on_chunk(n: int) -> None:
            if quiet or not total_bytes:
                return
            with progress_lock:
                seen_bytes[0] += n
                pct = 100.0 * seen_bytes[0] / total_bytes
                done, total = human_bytes(seen_bytes[0]), human_bytes(total_bytes)
                print(
                    f"\r  downloading {done}/{total} ({pct:.0f}%)",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
                progress_open[0] = True

        def clear_progress() -> None:
            """End the in-place progress line, once, if one is showing."""
            with progress_lock:
                if progress_open[0]:
                    print("", file=sys.stderr, flush=True)
                    progress_open[0] = False

        t0 = time.time()
        # Download every layer concurrently, but extract strictly in order so
        # each layer's whiteouts and overwrites land on the correct base.
        stats = ExtractStats()
        with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(layers)))) as pool:
            futures = [
                pool.submit(client.download_blob, layer.digest, blob_paths[i], on_chunk, verify)
                for i, layer in enumerate(layers)
            ]
            try:
                for i, layer in enumerate(layers):
                    # Future.result() blocks until this layer lands and re-raises
                    # any download error on this thread, so no manual Event or
                    # error-dict plumbing is needed.
                    futures[i].result()
                    clear_progress()
                    command = one_line(layer.command or layer.digest)
                    log(
                        f"  [{i + 1}/{len(layers)}] extract {human_bytes(layer.size):>8}  {command}"
                    )
                    with open_layer_stream(blob_paths[i], layer.media_type) as stream:
                        extract_layer(stream, dest, stats)
                    if not keep_tar:
                        try:
                            os.remove(blob_paths[i])
                        except OSError:
                            pass
            except BaseException:
                # Don't make the user wait on downloads whose output is now moot.
                clear_progress()
                for f in futures:
                    f.cancel()
                raise
        work_s = time.time() - t0

        if not keep_tar:
            shutil.rmtree(cache_dir, ignore_errors=True)

        image_cfg = config.get("config") or {}
        meta = {
            "image": image.pretty,
            "registry": image.registry,
            "platform": f"{os_name}/{arch}",
            "layers": [
                {"digest": layer.digest, "size": layer.size, "command": layer.command}
                for layer in layers
            ],
            "config": {
                k: image_cfg.get(k) for k in ("Env", "Entrypoint", "Cmd", "WorkingDir", "User")
            },
            "extracted": stats.as_dict(),
            # A census of the tree as it stands right now, so a later run of
            # `dt verify` can tell a complete folder from one that lost files
            # to a full disk, an interrupted copy, or a stray rm.
            "rootfs": scan_tree(dest).as_dict(),
            "layer_count": len(layers),
            "compressed_bytes": total_bytes,
            "verified_digests": bool(verify),
            # Written last, so this key can only be true if every layer was
            # downloaded, verified and extracted.
            "complete": True,
        }
        _write_record(dest, meta)

        log(f"  {stats}")
        log(f"done in {time.time() - started:.2f}s (fetch+extract {work_s:.2f}s)")
        return dest
    finally:
        client.close()


def _write_record(dest: str, meta: dict) -> None:
    """Write `.image.json` atomically.

    Verification treats this file's presence as proof the pull finished, so a
    half-written one would be a lie. Write to a sibling temp file and rename,
    which is atomic on every platform we target.
    """
    final = os.path.join(dest, IMAGE_META_NAME)
    tmp = final + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, final)
