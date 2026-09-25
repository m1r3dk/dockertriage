"""Download a Docker image and extract its full rootfs to a folder.

No daemon, no root, no dependencies. The public API is what this module
re-exports; everything else is an implementation detail and may move.

    from dockertriage import pull
    dest = pull("alpine:3.19", "./out")
"""

from __future__ import annotations

from .batch import BatchResult, pull_many, read_image_list
from .errors import RateLimited
from .extract import ExtractStats, extract_layer, open_layer_stream, safe_join, safe_relpath
from .manifest import Layer, pick_platform_manifest, resolve_layers
from .preflight import AccessResult, check_access, check_many
from .puller import pull
from .ratelimit import RateBudget, check_rate_budget
from .reference import ImageRef, parse_image
from .registry import RegistryClient
from .tags import newest_tag
from .verify import (
    CHECK_HELP,
    Check,
    TreeStats,
    VerifyResult,
    scan_tree,
    verify_dest,
    verify_list,
    verify_output_dir,
)
from .version import __version__

__all__ = [
    "CHECK_HELP",
    "AccessResult",
    "BatchResult",
    "Check",
    "ExtractStats",
    "ImageRef",
    "Layer",
    "RateBudget",
    "RateLimited",
    "RegistryClient",
    "TreeStats",
    "VerifyResult",
    "__version__",
    "check_access",
    "check_many",
    "check_rate_budget",
    "extract_layer",
    "newest_tag",
    "open_layer_stream",
    "parse_image",
    "pick_platform_manifest",
    "pull",
    "pull_many",
    "read_image_list",
    "resolve_layers",
    "safe_join",
    "safe_relpath",
    "scan_tree",
    "verify_dest",
    "verify_list",
    "verify_output_dir",
]
