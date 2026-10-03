"""Download a GitHub repository to a folder, the way an image becomes a rootfs.

The working tree comes from a single tarball, so a plain download needs no
git binary and no clone. Public repositories go through codeload, which is
outside the REST API's 60-an-hour anonymous limit; with `GITHUB_TOKEN` (or
`GH_TOKEN`) set, the API tarball endpoint is used instead, which is what
makes private repositories work.

History is opt-in. Secrets deleted in a later commit are still in the
repository, and are often the most valuable finding, but fetching them
means a full clone. `history=True` keeps a bare clone beside the tree, in
`.history.git`, where the secrets command reads it as git history.

The folder carries the same `.image.json` record a pulled image does, so
`st verify` and `st secrets` treat a repository like any other target.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

from .constants import CHUNK, GITHUB_API, GITHUB_CODELOAD, HISTORY_DIR_NAME, USER_AGENT
from .extract import ExtractStats, PathFilter, safe_join, safe_relpath
from .humanize import human_bytes
from .reference import RepoRef, parse_repo
from .tls import ssl_context
from .verify import scan_tree, write_record


def github_token() -> str | None:
    """A token from the environment, under either name GitHub's own tools use."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def _headers(token: str | None, accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Drop the token when the API hands the download off to codeload.

    The redirect target is a pre-signed URL; sending a credential along to
    another host is never necessary and is how tokens leak.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


def _open(url: str, headers: dict[str, str], timeout: float) -> Any:
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_context()), _NoAuthOnRedirect()
    )
    return opener.open(urllib.request.Request(url, headers=headers), timeout=timeout)


def _explain_http(repo: RepoRef, exc: urllib.error.HTTPError, token: str | None) -> str:
    """Turn GitHub's status codes into the reason a user can act on."""
    what = repo.slug + (f" at {repo.ref!r}" if repo.ref else "")
    if exc.code == 404 or (exc.code == 401 and not token):
        hint = "" if token else " (set GITHUB_TOKEN if it is private)"
        return f"{what} not found: no such repository or ref, or it is private{hint}"
    if exc.code == 401:
        return f"GITHUB_TOKEN was rejected for {repo.slug}"
    if exc.code in (403, 429) and exc.headers.get("X-RateLimit-Remaining") == "0":
        return "GitHub API rate limit reached; set GITHUB_TOKEN to raise it"
    if exc.code == 403:
        return f"access to {repo.slug} refused (HTTP 403)"
    return f"GitHub returned HTTP {exc.code} for {what}"


def tarball_url(repo: RepoRef, token: str | None) -> str:
    ref = urllib.parse.quote(repo.ref or "HEAD", safe="/")
    if token:
        return f"{GITHUB_API}/repos/{repo.slug}/tarball/{ref}"
    return f"{GITHUB_CODELOAD}/{repo.slug}/tar.gz/{ref}"


def download_tarball(
    repo: RepoRef,
    path: str,
    token: str | None = None,
    timeout: float = 60.0,
    on_chunk: Callable[[int], None] | None = None,
) -> int:
    """Stream the repository tarball to `path`. Returns bytes written."""
    try:
        with _open(tarball_url(repo, token), _headers(token), timeout) as resp:
            written = 0
            with open(path, "wb") as out:
                while chunk := resp.read(CHUNK):
                    out.write(chunk)
                    written += len(chunk)
                    if on_chunk is not None:
                        on_chunk(len(chunk))
            return written
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_explain_http(repo, exc, token)) from None


def extract_tarball(
    path: str,
    dest: str,
    stats: ExtractStats,
    path_filter: PathFilter | None = None,
) -> str:
    """Unpack a GitHub tarball into `dest`, dropping its top-level folder.

    Returns the commit sha GitHub records in the archive's pax comment, so
    the record names exactly what was downloaded even when the request said
    only `HEAD` or a branch.

    Every path is confined to `dest`. Symlinks are kept as links, never
    followed, so a link to `/etc/passwd` in a hostile repo stays a link.
    """
    links: list[tarfile.TarInfo] = []
    with tarfile.open(path, mode="r|gz") as tf:
        for member in tf:
            rel = safe_relpath(member.name.partition("/")[2])
            if rel is None:
                # The wrapper folder itself, or something trying to escape.
                if member.name.strip("/") and "/" in member.name.strip("/"):
                    stats.skipped += 1
                continue
            if path_filter is not None and not path_filter.wants(rel):
                stats.filtered += 1
                continue
            try:
                dst = safe_join(dest, rel)
            except ValueError:
                stats.skipped += 1
                continue
            if member.isdir():
                os.makedirs(dst, exist_ok=True)
                stats.dirs += 1
            elif member.issym():
                links.append(member)
            elif member.isreg():
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    stats.skipped += 1
                    continue
                # Owner-writable, keeping git's executable bit.
                mode = 0o755 if member.mode & 0o111 else 0o644
                fd = os.open(dst, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
                with os.fdopen(fd, "wb") as out:
                    shutil.copyfileobj(src, out, CHUNK)
                stats.files += 1
            else:
                # git stores only files, directories, symlinks and submodule
                # pointers; anything else in a tarball is not from git.
                stats.skipped += 1
        sha = str((tf.pax_headers or {}).get("comment", "")).strip()
    for member in links:
        dst = safe_join(dest, safe_relpath(member.name.partition("/")[2]) or "")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            os.symlink(member.linkname, dst)
            stats.symlinks += 1
        except OSError:
            # Windows without the symlink privilege, mostly.
            stats.skipped += 1
    return sha


def clone_history(repo: RepoRef, dest: str, token: str | None, timeout: float = 1800.0) -> None:
    """Keep a bare clone of every branch and tag at `dest`.

    Uses the git binary, which only this optional step needs. The token goes
    in through git's environment config, so it never lands in the clone's
    config file or a process listing.

    GitHub's git endpoint takes a token as Basic auth, not Bearer: measured,
    a Bearer header falls through to an interactive username prompt.
    """
    git = shutil.which("git")
    if not git:
        raise RuntimeError("--history needs git installed; the tree download itself does not")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
            GIT_CONFIG_VALUE_0=f"Authorization: Basic {basic}",
        )
    proc = subprocess.run(  # noqa: S603 - argv list, never a shell string
        [git, "clone", "--bare", "--quiet", f"https://github.com/{repo.slug}.git", dest],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise RuntimeError(
            f"git clone of {repo.slug} failed: {detail[-1] if detail else proc.returncode}"
        )


def pull_repo(
    repo_input: str,
    out_dir: str,
    quiet: bool = False,
    dest_override: str | None = None,
    paths: Sequence[str] | None = None,
    history: bool = False,
    on_progress: Callable[[int, int], None] | None = None,
    timeout: float = 60.0,
) -> str:
    """Download one repository's tree into a folder and return its path."""
    started = time.time()

    def log(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr, flush=True)

    repo = parse_repo(repo_input)
    token = github_token()
    path_filter = PathFilter(paths) if paths else None

    log("")
    log(f"github.com/{repo.slug}")
    log(f"@{repo.ref}" if repo.ref else "default branch")
    if path_filter:
        log(f"keeping only {', '.join('/' + p for p in path_filter.paths)}")
    log("")

    dest = os.path.abspath(dest_override or os.path.join(out_dir, repo.folder_name))

    seen = [0]

    def on_chunk(n: int) -> None:
        seen[0] += n
        if on_progress is not None:
            # GitHub streams tarballs without a length; the batch bar still
            # moves on the byte count.
            on_progress(seen[0], 0)
        elif not quiet:
            print(f"\rdownloading {human_bytes(seen[0])}", end="", file=sys.stderr, flush=True)

    stats = ExtractStats()
    tmp = tempfile.mkdtemp(prefix="srctriage-")
    try:
        archive = os.path.join(tmp, "repo.tar.gz")
        # Download before touching the destination, so a missing repository
        # or a typo leaves no empty folder behind for `st verify` to flag.
        size = download_tarball(repo, archive, token, timeout, on_chunk)
        if not quiet and on_progress is None:
            print("", file=sys.stderr, flush=True)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        os.makedirs(dest, exist_ok=True)
        sha = extract_tarball(archive, dest, stats, path_filter)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if history:
        log("cloning full history for the secrets scan...")
        try:
            clone_history(repo, os.path.join(dest, HISTORY_DIR_NAME), token)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            # The tree is fine, but the user asked for history and did not get
            # it. Leave no half-clone, and no record claiming a finished pull,
            # so `st verify` reports this folder rather than passing it.
            shutil.rmtree(os.path.join(dest, HISTORY_DIR_NAME), ignore_errors=True)
            raise RuntimeError(f"tree downloaded, but history was not: {exc}") from None

    meta: dict[str, Any] = {
        "kind": "github",
        "image": repo.pretty,
        "registry": "github",
        "repository": repo.slug,
        "ref": repo.ref,
        "commit": sha,
        # One "layer": the archive. Keeps verification's "something was
        # recorded" check meaningful without inventing a second schema.
        "layers": [{"digest": f"git:{sha}", "size": size, "command": f"tarball {repo.pretty}"}],
        "history": HISTORY_DIR_NAME if history else None,
        "extracted": stats.as_dict(),
        "rootfs": scan_tree(dest).as_dict(),
        "layer_count": 1,
        "compressed_bytes": size,
        "filter": {"paths": list(path_filter.paths)} if path_filter else None,
        "complete": True,
    }
    write_record(dest, meta)

    empty = [p for p, n in (path_filter.match_counts().items() if path_filter else []) if not n]
    log(f"commit {sha[:12] or 'unknown'}  {human_bytes(size)} downloaded")
    log(f"{stats}")
    for p in empty:
        log(f"--path /{p} matched nothing in this repository")
    log(f"done in {time.time() - started:.2f}s")
    log("")
    return dest


def check_repo_access(repo_input: str, timeout: float = 30.0) -> tuple[str, str]:
    """Return (status, detail) using the preflight's vocabulary.

    A HEAD on the tarball URL answers "does this repo and ref exist and can
    we read it" without downloading anything.
    """
    try:
        repo = parse_repo(repo_input)
    except ValueError as exc:
        return "error", str(exc)
    token = github_token()
    url = tarball_url(repo, token)
    req = urllib.request.Request(url, headers=_headers(token), method="HEAD")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_context()), _NoAuthOnRedirect()
    )
    try:
        with opener.open(req, timeout=timeout):
            return "ok", ""
    except urllib.error.HTTPError as exc:
        detail = _explain_http(repo, exc, token)
        if "rate limit" in detail:
            return "rate_limited", detail
        if exc.code == 404 and repo.ref:
            return "missing_tag", detail
        if exc.code in (401, 403, 404):
            return "inaccessible", detail
        return "error", detail
    except Exception as exc:  # noqa: BLE001 - a preflight must never be fatal
        return "error", f"{type(exc).__name__}: {exc}"


def describe(repo_input: str, timeout: float = 30.0) -> dict[str, Any]:
    """Repository metadata for `st inspect`, from the REST API."""
    repo = parse_repo(repo_input)
    token = github_token()
    try:
        with _open(f"{GITHUB_API}/repos/{repo.slug}", _headers(token), timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_explain_http(repo, exc, token)) from None
    return {
        "repository": data.get("full_name") or repo.slug,
        "ref": repo.ref or data.get("default_branch"),
        "description": data.get("description") or "",
        "visibility": data.get("visibility") or ("private" if data.get("private") else "public"),
        "size_kb": data.get("size") or 0,
        "language": data.get("language") or "",
        "archived": bool(data.get("archived")),
        "pushed_at": data.get("pushed_at") or "",
        "clone_url": data.get("clone_url") or f"https://github.com/{repo.slug}.git",
    }


def resolve_commit(repo_input: str, timeout: float = 30.0) -> str:
    """The commit sha a ref (or the default branch) points at right now."""
    repo = parse_repo(repo_input)
    token = github_token()
    ref = urllib.parse.quote(repo.ref or "HEAD", safe="/")
    url = f"{GITHUB_API}/repos/{repo.slug}/commits/{ref}"
    try:
        with _open(url, _headers(token, "application/vnd.github.sha"), timeout) as resp:
            return resp.read().decode().strip()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_explain_http(repo, exc, token)) from None
