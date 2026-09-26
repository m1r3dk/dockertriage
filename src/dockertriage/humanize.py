"""Formatting helpers for human-facing output."""

__all__ = ["human_bytes", "one_line", "short_digest", "build_step"]

# Noise every buildkit image repeats on most layers. Stripping it leaves the
# part of the command that actually differs between one layer and the next.
_PREFIXES = ("RUN /bin/sh -c ", "/bin/sh -c ", "RUN ")
_SUFFIX = "# buildkit"


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


def short_digest(digest: str, keep: int = 12) -> str:
    """`sha256:4da4fc9c4800…` instead of 71 characters of hex.

    The full digest is never the point when reading a layer list; the first
    few bytes already identify it, and the rest only pushes real content off
    the line.
    """
    algo, _, hexpart = digest.partition(":")
    if not hexpart:
        return digest[:keep]
    return f"{algo}:{hexpart[:keep]}"


def build_step(command: str) -> tuple[str, str]:
    """Split a history entry into its verb and the rest.

    `RUN /bin/sh -c apt-get update` is mostly boilerplate: every layer of a
    Debian image starts the same way, so the shell wrapper carries no
    information and crowds out the part that does. Returns (verb, detail) so
    a caller can style them separately.
    """
    text = " ".join((command or "").split())
    if text.endswith(_SUFFIX):
        text = text[: -len(_SUFFIX)].rstrip()

    for verb in ("COPY", "ADD", "WORKDIR", "ENV", "CMD", "ENTRYPOINT", "USER", "EXPOSE"):
        if text.upper().startswith(verb + " "):
            return verb, text[len(verb) + 1 :].strip()

    for prefix in _PREFIXES:
        if text.startswith(prefix):
            return "RUN", text[len(prefix) :].strip()

    # Base-image layers carry a build script comment rather than a verb.
    if text.startswith("#"):
        return "BASE", text.lstrip("# ").strip()
    return "", text
