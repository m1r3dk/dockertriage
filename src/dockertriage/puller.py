"""Pull one image and leave a merged rootfs on disk.

Layers download in parallel but extract strictly in order, so a later
layer's whiteouts always land on the base they were built against.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

from . import coverage
from .constants import IMAGE_META_NAME, LAYER_CACHE_NAME
from .extract import ExtractStats, PathFilter, extract_layer, open_layer_stream
from .humanize import INDEX_W, SIZE_W, human_bytes, layer_row, short_digest, size_bar
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
    paths: Sequence[str] | None = None,
    use_workdir: bool = False,
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

        # Build the path filter, if one was asked for. --app resolves against
        # the image's own WorkingDir, and fails loudly when the image does not
        # declare one rather than silently extracting the whole filesystem.
        wanted_paths: list[str] = list(paths or [])
        if use_workdir:
            workdir = coverage.working_dir(config)
            if not workdir:
                raise RuntimeError(
                    f"{image.pretty} declares no WorkingDir, so there is no app "
                    "directory to infer. Pass --path explicitly."
                )
            wanted_paths.append(workdir)
        path_filter = PathFilter(wanted_paths) if wanted_paths else None

        # Header mirrors `dt inspect`: name, then reference, then platform,
        # each on its own line so a 71-character digest never wraps.
        log("")
        log(image.repo)
        if image.is_digest:
            log(f"@{short_digest(image.ref, 16)} digest")
        else:
            log(f":{image.ref}")
        log(f"{os_name}/{arch}")
        if image.ref_inferred:
            log("no 'latest' tag; using the newest one")
        if path_filter:
            log(f"keeping only {', '.join('/' + p for p in path_filter.paths)}")
        log("")
        log(
            f"{len(layers)} {'layer' if len(layers) == 1 else 'layers'}  "
            f"{human_bytes(total_bytes)} compressed  (resolved in {resolve_s:.2f}s)"
        )
        log("")

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
                # Indented under the layer rows, with the same bar the rows
                # use, so downloading reads as part of the same display.
                bar = size_bar(seen_bytes[0], total_bytes)
                # Padded to a fixed width so the shrinking percentage cannot
                # leave a stale tail behind, but kept short enough that the
                # line never wraps, which would strand the \r on the wrong row.
                tail = f"downloading {done}/{total} ({pct:.0f}%)"
                line = f"{'':>{INDEX_W}} {'':>{SIZE_W}} {bar} {tail:<34}"
                print(f"\r{line}", end="", file=sys.stderr, flush=True)
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
        # Scale for the per-layer bars, so pull and inspect draw them alike.
        largest_layer = max((layer.size for layer in layers), default=0)
        term_width = max(60, min(shutil.get_terminal_size((100, 20)).columns, 120))
        # layer index -> entries it put into the output. Only meaningful under a
        # filter, where it shows which layers actually held the wanted files.
        layer_hits: dict[int, int] = {}
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
                    # Same row layout as `dt inspect`, so the two commands
                    # describe a layer the same way.
                    log(
                        layer_row(
                            i + 1,
                            layer.size,
                            largest_layer,
                            layer.command or short_digest(layer.digest),
                            term_width,
                        )
                    )
                    with open_layer_stream(blob_paths[i], layer.media_type) as stream:
                        added = extract_layer(stream, dest, stats, path_filter=path_filter)
                    if added:
                        layer_hits[i] = added
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
        # Under a filter, check the result against the image's own history so
        # the user is told what was left out instead of having to guess.
        report = None
        if path_filter:
            report = coverage.build_report(
                path_filter.paths,
                [layer.command for layer in layers],
                path_filter.match_counts(),
                layer_hits,
                stats.unresolved_links,
            )
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
            # Present only for a filtered pull. Its absence means "whole image",
            # which is what lets `dt verify` tell a partial tree from a broken
            # one instead of calling every filtered pull incomplete.
            "filter": report.as_dict() if report else None,
            # Written last, so this key can only be true if every layer was
            # downloaded, verified and extracted.
            "complete": True,
        }
        _write_record(dest, meta)

        log("")
        log(f"{stats}")
        if report:
            for line in report.lines():
                log(line)
        log(f"done in {time.time() - started:.2f}s (fetch+extract {work_s:.2f}s)")
        log("")
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
