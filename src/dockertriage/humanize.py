"""Formatting helpers for human-facing output."""

from __future__ import annotations

__all__ = ["human_bytes", "one_line"]


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def one_line(text: str, width: int = 74) -> str:
    """Collapse a Dockerfile command to a single, bounded line.

    buildkit embeds tabs and newlines in `created_by`, which otherwise print
    verbatim and wreck the layer list. Squash all runs of whitespace to one
    space, then truncate with an ellipsis so the column stays aligned.
    """
    collapsed = " ".join(text.split())
    if len(collapsed) > width:
        collapsed = collapsed[: width - 1] + "…"
    return collapsed
