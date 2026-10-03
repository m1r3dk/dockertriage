"""Formatting helpers for human-facing output.

The layout constants live here rather than in the CLI because `st pull`
prints progress from the stdlib-only library modules while `st inspect`
renders through rich. Both read from this file, so a layer line looks the
same whichever command produced it.
"""

# Noise every buildkit image repeats on most layers. Stripping it leaves the
# part of the command that actually differs between one layer and the next.
_PREFIXES = ("RUN /bin/sh -c ", "/bin/sh -c ", "RUN ")
_SUFFIX = "# buildkit"

# Shared column widths: index, size, and the proportional bar. The step text
# takes whatever is left, so only these three need to agree between commands.
INDEX_W = 3
SIZE_W = 8
BAR_W = 10

# Eighths of a block, so a bar can show a fraction of a column.
_BLOCKS = "▏▎▍▌▋▊▉█"


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


def size_bar(size: int, largest: int, width: int = BAR_W) -> str:
    """A proportional bar, so the layers carrying the weight are obvious."""
    if largest <= 0 or size <= 0:
        return " " * width
    eighths = max(1, round(width * 8 * size / largest))
    full, rest = divmod(eighths, 8)
    bar = "█" * min(full, width)
    if rest and full < width:
        bar += _BLOCKS[rest - 1]
    return bar.ljust(width)


def layer_row(index: int, size: int, largest: int, command: str, width: int = 100) -> str:
    """One plain-text layer line, shared by `st pull` and `st inspect`.

    Returns unstyled text; a caller with rich available can colour the verb
    afterwards. Keeping the arithmetic here is what stops the two commands
    drifting into different-looking output.
    """
    step_w = max(20, width - (INDEX_W + SIZE_W + BAR_W + 4))
    verb, detail = build_step(command)
    label = f"{verb} {detail}".strip() if verb else detail
    return (
        f"{index:>{INDEX_W}} "
        f"{human_bytes(size):>{SIZE_W}} "
        f"{size_bar(size, largest)} "
        f"{one_line(label, step_w)}"
    )
