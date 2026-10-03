"""Tag ordering.

Used to recover when the 'latest' we assumed does not exist.
"""

import re


def natural_key(tag: str) -> tuple:
    """Sort tags so v9 < v10, rather than lexically where v10 < v9."""
    parts = re.split(r"(\d+)", tag)
    return tuple((1, int(p)) if p.isdigit() else (0, p) for p in parts if p)


def newest_tag(tags: list[str]) -> str | None:
    """Best guess at the tag a human would call 'the current one'.

    Prefers the conventional moving tags, then the highest-numbered one.
    """
    if not tags:
        return None
    for preferred in ("latest", "main", "master", "stable", "prod", "production"):
        if preferred in tags:
            return preferred
    return sorted(tags, key=natural_key)[-1]
