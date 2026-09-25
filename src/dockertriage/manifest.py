"""Resolve a reference to the ordered list of real layers.

Two traps live here: buildkit attestation entries masquerade as platforms,
and config history contains metadata-only steps with no layer behind them.
"""

from __future__ import annotations

from typing import Any

from .constants import INDEX_TYPES
from .registry import RegistryClient
from .tags import natural_key, newest_tag

__all__ = ["Layer", "pick_platform_manifest", "resolve_layers"]


def pick_platform_manifest(index: dict[str, Any], os_name: str, arch: str) -> str:
    manifests = [m for m in (index.get("manifests") or []) if m.get("digest")]
    if not manifests:
        raise RuntimeError("manifest index contains no entries")

    def plat(m):
        return m.get("platform") or {}

    real = [m for m in manifests if plat(m).get("architecture") not in (None, "unknown")]
    pool = real or manifests

    for m in pool:
        p = plat(m)
        if p.get("os") == os_name and p.get("architecture") == arch:
            return m["digest"]
    for m in pool:
        p = plat(m)
        if p.get("os") == os_name and p.get("architecture") in ("amd64", "x86_64"):
            return m["digest"]
    for m in pool:
        if plat(m).get("os") == os_name:
            return m["digest"]
    return pool[0]["digest"]


class Layer:
    __slots__ = ("index", "digest", "size", "media_type", "command")

    def __init__(self, index: int, digest: str, size: int, media_type: str, command: str = ""):
        self.index = index
        self.digest = digest
        self.size = size
        self.media_type = media_type
        self.command = command


def resolve_layers(
    client: RegistryClient, os_name: str, arch: str, strict_tag: bool = False
) -> tuple[list[Layer], dict[str, Any]]:
    """Resolve an image reference down to its ordered list of real layers."""
    try:
        manifest, ctype = client.get_manifest(client.image.ref)
    except RuntimeError as exc:
        # 'latest' is our default, not the user's request. Plenty of repos
        # never publish it, so failing on a tag we invented is our bug, not
        # the user's. Fall back to the newest real tag instead.
        if "not found" not in str(exc) or not client.image.ref_implicit:
            raise
        tags = client.list_tags()
        best = newest_tag(tags)
        if not best:
            raise
        if strict_tag:
            ordered = sorted(tags, key=natural_key)
            shown = ", ".join(ordered[:10]) + (" ..." if len(ordered) > 10 else "")
            raise RuntimeError(
                f"{client.image.repo} has no 'latest' tag. "
                f"Available: {shown}. Use {client.image.repo}:{best} "
                f"or drop --strict-tag to pick one automatically"
            ) from None
        client.image.ref = best
        client.image.ref_implicit = False
        client.image.ref_inferred = True
        manifest, ctype = client.get_manifest(best)

    if ctype in INDEX_TYPES or ("manifests" in manifest and "layers" not in manifest):
        digest = pick_platform_manifest(manifest, os_name, arch)
        manifest, ctype = client.get_manifest(digest)

    raw_layers = manifest.get("layers") or []
    if not raw_layers:
        raise RuntimeError("manifest has no layers (is this an image manifest?)")

    config: dict[str, Any] = {}
    cfg_digest = (manifest.get("config") or {}).get("digest")
    if cfg_digest:
        try:
            config = client.get_blob_json(cfg_digest)
        except Exception:
            config = {}

    # Align history entries (which include metadata-only steps) with real layers
    # so we can label each layer with the Dockerfile command that made it.
    commands: list[str] = []
    for h in config.get("history") or []:
        if not h.get("empty_layer"):
            commands.append((h.get("created_by") or "").strip())

    layers: list[Layer] = []
    for i, raw in enumerate(raw_layers):
        digest = raw.get("digest")
        if not digest:
            raise RuntimeError(f"layer {i} missing digest")
        layers.append(
            Layer(
                index=i,
                digest=digest,
                size=int(raw.get("size") or 0),
                media_type=raw.get("mediaType") or "",
                command=commands[i] if i < len(commands) else "",
            )
        )
    return layers, config
