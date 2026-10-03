"""Download container images and GitHub repositories to a folder, then triage them.

No daemon, no root, no dependencies. The public API is what this module
re-exports; everything else is an implementation detail and may move.

    from srctriage import pull
    dest = pull("alpine:3.19", "./out")              # merged rootfs
    repo = pull("github.com/octocat/Hello-World", "./out")  # working tree
"""

from .batch import BatchResult, pull_many, read_image_list
from .extract import (
    ExtractStats,
    PathFilter,
    extract_layer,
    open_layer_stream,
    safe_join,
    safe_relpath,
)
from .github import pull_repo
from .manifest import Layer, pick_platform_manifest, resolve_layers
from .preflight import AccessResult, check_access, check_many
from .puller import pull
from .ratelimit import RateBudget, check_rate_budget
from .reference import ImageRef, RepoRef, is_repo_ref, parse_image, parse_repo
from .registry import RateLimited, RegistryClient
from .secretreport import DEFAULT_OUTPUT_DIR, write_report
from .secrets import (
    Finding,
    ScanCoverage,
    ScanResult,
    SecretScan,
    available_engines,
    discover_targets,
    scan_tree_for_secrets,
)
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
    "DEFAULT_OUTPUT_DIR",
    "AccessResult",
    "BatchResult",
    "Check",
    "ExtractStats",
    "Finding",
    "ImageRef",
    "Layer",
    "PathFilter",
    "RateBudget",
    "RateLimited",
    "RegistryClient",
    "RepoRef",
    "ScanCoverage",
    "ScanResult",
    "SecretScan",
    "TreeStats",
    "VerifyResult",
    "__version__",
    "available_engines",
    "check_access",
    "check_many",
    "check_rate_budget",
    "discover_targets",
    "extract_layer",
    "is_repo_ref",
    "newest_tag",
    "open_layer_stream",
    "parse_image",
    "parse_repo",
    "pick_platform_manifest",
    "pull",
    "pull_many",
    "pull_repo",
    "read_image_list",
    "resolve_layers",
    "safe_join",
    "safe_relpath",
    "scan_tree",
    "scan_tree_for_secrets",
    "verify_dest",
    "verify_list",
    "verify_output_dir",
    "write_report",
]
