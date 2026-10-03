"""Turn what a user types into a registry coordinate or a GitHub repository.

Accepts bare names, tags, digests and the web URLs people actually copy out
of a browser, because those are what land in an image list.
"""

import dataclasses
import re
import urllib.parse

from .constants import DOCKERHUB_REGISTRY, ECR_PUBLIC_REGISTRY


class ImageRef:
    __slots__ = ("registry", "host", "repo", "ref", "is_digest", "ref_implicit", "ref_inferred")

    def __init__(
        self, registry: str, host: str, repo: str, ref: str | None, is_digest: bool = False
    ):
        self.registry = registry
        self.host = host
        self.repo = repo
        # Remember whether ':latest' was the user's choice or our default, so
        # a missing 'latest' can suggest the tags that do exist.
        self.ref_implicit = not ref
        self.ref = ref or "latest"
        self.is_digest = is_digest
        # Set when we had to choose a tag because 'latest' did not exist.
        self.ref_inferred = False

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        sep = "@" if self.is_digest else ":"
        return f"<ImageRef {self.host}/{self.repo}{sep}{self.ref}>"

    @property
    def pretty(self) -> str:
        """repo:tag or repo@sha256:... , the way a user would type it."""
        return f"{self.repo}{'@' if self.is_digest else ':'}{self.ref}"

    @property
    def folder_name(self) -> str:
        safe_ref = "".join(c if c.isalnum() or c in "_.-" else "_" for c in self.ref)
        if self.is_digest:
            safe_ref = safe_ref.replace("sha256_", "")[:16]
        else:
            safe_ref = safe_ref[:32]
        return f"{self.repo.replace('/', '_')}_{safe_ref}"


def _normalize_repo(repo: str) -> str:
    repo = repo.strip().strip("/")
    if not repo:
        raise ValueError("empty repository name")
    if repo.count("/") == 0:
        repo = f"library/{repo}"
    if repo.count("/") != 1:
        raise ValueError(f"repo must be 'name' or 'namespace/name', got {repo!r}")
    return repo


def _split_ref(s: str) -> tuple[str, str | None, bool]:
    """Return (name, ref, is_digest)."""
    s = s.strip()
    if "@" in s:
        name, ref = s.split("@", 1)
        return name.strip(), ref.strip() or None, True
    if ":" in s:
        name, ref = s.rsplit(":", 1)
        # a port in a registry host is not a tag: 'localhost:5000/foo'
        if "/" in ref:
            return s, None, False
        return name.strip(), ref.strip() or None, False
    return s, None, False


def parse_image(raw: str) -> ImageRef:
    """Accept repo, repo:tag, repo@sha256:..., or a hub.docker.com / ECR URL."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty image reference")

    candidate = raw
    bare_host_prefixes = ("hub.docker.com/", "gallery.ecr.aws/", "public.ecr.aws/")
    looks_like_url = "://" in candidate
    if not looks_like_url and candidate.startswith(bare_host_prefixes):
        # public.ecr.aws/foo/bar is a valid pull reference too, but only the
        # gallery/hub web URLs need the https:// treatment.
        if not candidate.startswith("public.ecr.aws/"):
            candidate = "https://" + candidate
            looks_like_url = True

    if looks_like_url:
        return _parse_url(candidate)

    name, ref, is_digest = _split_ref(candidate)
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break

    if name.startswith("public.ecr.aws/"):
        repo = name[len("public.ecr.aws/") :].strip("/")
        parts = [p for p in repo.split("/") if p]
        if len(parts) < 2:
            raise ValueError("public ECR reference must be 'public.ecr.aws/registry/repo'")
        # Repository names may nest, e.g. flakybitnet/blocky/agh-data.
        return ImageRef("ecr_public", ECR_PUBLIC_REGISTRY, "/".join(parts), ref, is_digest)

    return ImageRef("dockerhub", DOCKERHUB_REGISTRY, _normalize_repo(name), ref, is_digest)


def _is_digest(ref: str | None) -> bool:
    algo, sep, _ = (ref or "").partition(":")
    return bool(sep) and algo in ("sha256", "sha512") and "@" not in (ref or "")


def _ref_from_query(query: str) -> str | None:
    """Pull a tag or digest out of a registry web URL's query string.

    Both hubs link specific images this way, e.g.
    `?digest=sha256:abc...` or `?tag=1.2.3`. Ignoring it silently pulls
    `latest` instead of the image the user actually pointed at.
    """
    if not query:
        return None
    params = urllib.parse.parse_qs(query)
    for key in ("digest", "tag", "ref"):
        values = params.get(key)
        if values and values[0].strip():
            return values[0].strip()
    return None


def _parse_url(url: str) -> ImageRef:
    """Parse a registry web URL (hub.docker.com, gallery.ecr.aws)."""
    u = urllib.parse.urlparse(url)
    host = (u.netloc or "").lower()
    parts = [p for p in (u.path or "").strip("/").split("/") if p]
    ref: str | None = None

    if host.endswith("hub.docker.com"):
        if len(parts) >= 3 and parts[0] == "r":
            leaf = parts[2]
            if ":" in leaf:
                leaf, ref = leaf.rsplit(":", 1)
            repo = f"{parts[1]}/{leaf}"
        elif len(parts) >= 2 and parts[0] == "_":
            leaf = parts[1]
            if ":" in leaf:
                leaf, ref = leaf.rsplit(":", 1)
            repo = f"library/{leaf}"
        elif len(parts) == 1:
            repo = f"library/{parts[0]}"
        else:
            raise ValueError(f"unsupported Docker Hub URL: {url}")
        # The hub UI links specific images as ?tag=... or ?digest=sha256:...
        ref = ref or _ref_from_query(u.query)
        return ImageRef(
            "dockerhub",
            DOCKERHUB_REGISTRY,
            _normalize_repo(repo),
            ref,
            is_digest=_is_digest(ref),
        )

    if host.endswith("gallery.ecr.aws") or host.endswith("public.ecr.aws"):
        if len(parts) < 2:
            raise ValueError(f"unsupported ECR Public URL: {url}")
        # ECR Public repositories are registry-alias/name, but the name itself
        # may contain slashes (flakybitnet/blocky/agh-data), so keep every
        # segment rather than assuming exactly two.
        leaf = parts[-1]
        if ":" in leaf:
            leaf, ref = leaf.rsplit(":", 1)
        repo = "/".join([*parts[:-1], leaf])
        ref = ref or _ref_from_query(u.query)
        return ImageRef("ecr_public", ECR_PUBLIC_REGISTRY, repo, ref, is_digest=_is_digest(ref))

    raise ValueError(f"unsupported registry host: {host or url}")


# ---------------------------------------------------------------------------
# GitHub repositories. Parsed here, beside images, so anything that maps a
# reference to its folder (verify, batch) needs one import and no network.
# ---------------------------------------------------------------------------

# GitHub's own rules for owner and repository names.
_GH_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclasses.dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str
    # Branch, tag or commit. None means the default branch.
    ref: str | None = None

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def pretty(self) -> str:
        """github.com/owner/repo[@ref], the form recorded and reported."""
        return f"github.com/{self.slug}" + (f"@{self.ref}" if self.ref else "")

    @property
    def folder_name(self) -> str:
        base = f"github_{self.owner}_{self.name}"
        if not self.ref:
            return base
        safe_ref = "".join(c if c.isalnum() or c in "_.-" else "_" for c in self.ref)
        return f"{base}_{safe_ref[:32]}"


def is_repo_ref(raw: str) -> bool:
    """True when `raw` names a GitHub repository rather than an image.

    Unambiguous by construction: no registry is called github.com (GitHub's
    is ghcr.io), and `gh:` cannot start an image reference.
    """
    s = (raw or "").strip().lower()
    if s.startswith(("gh:", "git@github.com:")):
        return True
    return s.split("://", 1)[-1].startswith(("github.com/", "www.github.com/"))


def parse_repo(raw: str) -> RepoRef:
    """Accept the forms people paste for a repository.

    gh:owner/repo, github.com/owner/repo, https://github.com/owner/repo.git,
    git@github.com:owner/repo.git, browser links to /tree/<ref>,
    /commit/<sha> and /releases/tag/<tag>, and an `@ref` suffix on any of
    them. A link into a folder (/tree/main/src) is refused rather than
    guessed at, because `main/src` is also a valid branch name.
    """
    s = (raw or "").strip()
    low = s.lower()
    if low.startswith("gh:"):
        rest = s[3:]
    elif low.startswith("git@github.com:"):
        rest = s[len("git@github.com:") :]
    else:
        rest = urllib.parse.urlparse(s if "://" in s else "https://" + s).path
    rest = rest.strip().strip("/")

    ref: str | None = None
    if "@" in rest:
        rest, ref = rest.split("@", 1)
        ref = ref.strip() or None
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"GitHub reference must name owner/repo, got {raw!r}")
    owner, name = parts[0], parts[1].removesuffix(".git")
    tail = parts[2:]
    if tail:
        if ref is not None:
            raise ValueError(f"give the ref once, either as @ref or in the URL path: {raw!r}")
        if tail[0] in ("tree", "commit") and len(tail) == 2:
            ref = tail[1]
        elif tail[:2] == ["releases", "tag"] and len(tail) == 3:
            ref = tail[2]
        elif tail[0] == "tree" and len(tail) > 2:
            raise ValueError(
                f"{raw!r} points into a folder, and the branch name is ambiguous. "
                f"Use github.com/{owner}/{name}@<ref> with --path <folder>."
            )
        else:
            raise ValueError(f"unsupported GitHub URL path: /{'/'.join(tail)}")
    for part in (owner, name):
        if not _GH_NAME.match(part):
            raise ValueError(f"not a valid GitHub owner or repository name: {part!r}")
    return RepoRef(owner, name, ref)


def folder_name_for(raw: str) -> str:
    """The folder a pull of `raw` writes, image or repository."""
    return parse_repo(raw).folder_name if is_repo_ref(raw) else parse_image(raw).folder_name
