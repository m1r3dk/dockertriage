"""Answer the question a filtered extraction has to answer: did I miss anything?

A filter like `--path /app` writes only part of the image, which is useful and
also dangerous, because the files it drops are invisible by definition. The
image config carries enough evidence to check the filter rather than trust it.

Two independent sources are used:

* `WorkingDir` from the image config, which is where the image itself says the
  application runs from.
* The `created_by` history, where every `COPY` and `ADD` records the path it
  wrote to. Those are the deliberate content-placing steps of a build, so a
  destination outside the filter is exactly the thing a user needs told.

The history is a hint, not proof: a `RUN` step can write anywhere and says
nothing about where. So the report never claims "nothing was missed"; it
reports what the evidence shows and is explicit about that limit.
"""

import dataclasses
import posixpath
import shlex
from typing import Any

# Trailing buildkit marker on modern history entries: "COPY x y # buildkit".
_BUILDKIT_SUFFIX = "# buildkit"


@dataclasses.dataclass(slots=True)
class CopyDestination:
    """One path a COPY or ADD step wrote to, and whether the filter kept it."""

    layer_index: int
    verb: str
    path: str
    command: str
    covered: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer_index + 1,
            "verb": self.verb,
            "path": self.path,
            "covered": self.covered,
        }


def working_dir(config: dict[str, Any]) -> str:
    """The image's WorkingDir, or '' when it is unset or meaningless.

    '/' is treated as unset: it is the default for images that never declare
    one, and filtering on '/' would keep the whole filesystem.
    """
    value = ((config.get("config") or {}).get("WorkingDir") or "").strip()
    return "" if value in ("", "/") else value


def _destination_from(command: str) -> str:
    """Pull the destination argument out of one COPY/ADD command string.

    Docker writes history as `COPY <src>... <dest>`, so the destination is the
    final argument. Flags like `--from=builder` and the buildkit marker are
    dropped first so they cannot be mistaken for it.
    """
    text = command.strip()
    if text.endswith(_BUILDKIT_SUFFIX):
        text = text[: -len(_BUILDKIT_SUFFIX)].strip()
    try:
        # posix=False keeps Windows-style paths intact; shlex still splits on
        # whitespace and respects quoting, which naive .split() would not.
        parts = shlex.split(text, posix=False)
    except ValueError:
        parts = text.split()
    # Drop the verb and any --flags, leaving the source/destination arguments.
    args = [p for p in parts[1:] if not p.startswith("--")]
    if len(args) < 2:
        # A one-argument form has no explicit destination to check.
        return ""
    return args[-1].strip("\"'")


def copy_destinations(layer_commands: list[str]) -> list[CopyDestination]:
    """Every COPY/ADD destination recorded in the image history, in order."""
    found: list[CopyDestination] = []
    for index, command in enumerate(layer_commands):
        text = (command or "").strip()
        upper = text.upper()
        for verb in ("COPY", "ADD"):
            if not upper.startswith(verb + " "):
                continue
            dest = _destination_from(text)
            if dest:
                found.append(CopyDestination(index, verb, dest, text))
            break
    return found


def _absolute(path: str) -> str:
    """Normalise a path to a single leading slash and no trailing slash.

    posixpath.normpath keeps a leading '//' (POSIX reserves it), so the slash
    is stripped before it is added back, otherwise '/app' and 'app' would not
    compare equal.
    """
    clean = posixpath.normpath("/" + path.replace("\\", "/").lstrip("/"))
    return clean.rstrip("/") or "/"


def _is_covered(dest: str, paths: tuple[str, ...]) -> bool:
    """True if a COPY destination falls inside one of the filtered paths."""
    clean = _absolute(dest)
    for raw in paths:
        prefix = _absolute(raw)
        if prefix == "/" or clean == prefix or clean.startswith(prefix + "/"):
            return True
        # A COPY into a parent of the filter still delivers the filtered files,
        # e.g. `COPY . /` placing /app/main.py when the filter is /app.
        if prefix.startswith(clean + "/") or clean == "/":
            return True
    return False


@dataclasses.dataclass(slots=True)
class FilterReport:
    """What a filtered extraction kept, and what the evidence says it dropped."""

    paths: tuple[str, ...]
    destinations: list[CopyDestination]
    match_counts: dict[str, int]
    layer_hits: dict[int, int]
    unresolved_links: int = 0

    @property
    def uncovered(self) -> list[CopyDestination]:
        """COPY/ADD destinations that fell outside the filter."""
        return [d for d in self.destinations if not d.covered]

    @property
    def empty_paths(self) -> list[str]:
        """Requested paths that matched nothing at all, usually a typo."""
        return [p for p, n in self.match_counts.items() if n == 0]

    @property
    def clean(self) -> bool:
        """True when every piece of evidence agrees nothing was left behind."""
        return not self.uncovered and not self.empty_paths and not self.unresolved_links

    def as_dict(self) -> dict[str, Any]:
        return {
            "paths": list(self.paths),
            "matched_per_path": self.match_counts,
            "contributing_layers": sorted(self.layer_hits),
            "copy_destinations": [d.as_dict() for d in self.destinations],
            "uncovered_destinations": [d.as_dict() for d in self.uncovered],
            "empty_paths": self.empty_paths,
            "unresolved_links": self.unresolved_links,
            "clean": self.clean,
        }

    def lines(self) -> list[str]:
        """Human-readable summary, one concern per line."""
        out: list[str] = []
        hits = sorted(n + 1 for n in self.layer_hits)
        shown = ", ".join(str(n) for n in hits) if hits else "none"
        out.append(f"kept {', '.join(self.paths)} from layer(s) {shown}")

        for path in self.empty_paths:
            out.append(f"WARNING: {path} matched nothing in this image")

        for dest in self.uncovered:
            out.append(
                f"outside the filter: {dest.verb} -> {dest.path} (layer {dest.layer_index + 1})"
            )

        if self.unresolved_links:
            out.append(
                f"WARNING: {self.unresolved_links} hardlink(s) point at files "
                "outside the filter and could not be written"
            )

        if self.clean:
            out.append("every COPY/ADD in this image landed inside the filter")
        return out


def build_report(
    paths: tuple[str, ...],
    layer_commands: list[str],
    match_counts: dict[str, int],
    layer_hits: dict[int, int],
    unresolved_links: int = 0,
) -> FilterReport:
    """Compare a filter against the image history and report the difference."""
    destinations = copy_destinations(layer_commands)
    for dest in destinations:
        dest.covered = _is_covered(dest.path, paths)
    return FilterReport(paths, destinations, match_counts, layer_hits, unresolved_links)
