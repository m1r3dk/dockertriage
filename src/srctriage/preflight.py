"""Find out which images are actually pullable before downloading any.

A list of a few hundred Docker Hub references always contains some that
cannot be fetched: the repo was deleted, made private, or taken down. Left
to the download loop those are discovered one at a time, interleaved with
real progress, after DNS and TLS and a token round trip each.

Checking first is cheap and honest. The registry hands out a token to
anyone, then refuses the manifest, and the token's own `access` claim
already says which it will be. A HEAD on the manifest then confirms the
tag exists. Neither request counts against the Docker Hub pull budget,
which is the property that makes a preflight over the whole list
affordable: measured against `ratelimitpreview`, 6 anonymous HEADs moved
the remaining count by zero.
"""

import dataclasses
import http.client
import urllib.parse
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .constants import MANIFEST_ACCEPT, USER_AGENT
from .reference import parse_image
from .registry import RateLimited, RegistryClient
from .tls import ssl_context

# Why an image cannot be pulled, in the words a user would use for it.
REASONS = {
    "ok": "pullable",
    "inaccessible": "private, deleted, or taken down",
    "missing_tag": "repository exists but the tag does not",
    "rate_limited": "registry rate limit reached before it could be checked",
    "error": "could not be checked",
}


@dataclasses.dataclass
class AccessResult:
    """Whether one reference can be pulled, and why not when it cannot."""

    image: str
    status: str = "ok"
    detail: str = ""
    # Filled when the repo exists but the tag does not, so the message can
    # suggest something real instead of just saying no.
    available_tags: list[str] = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def reason(self) -> str:
        return REASONS.get(self.status, self.status)

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"image": self.image, "ok": self.ok, "status": self.status}
        if self.detail:
            d["detail"] = self.detail
        if self.available_tags:
            d["available_tags"] = self.available_tags[:10]
        return d


def _head_manifest(client: RegistryClient, repo: str, ref: str, timeout: float) -> int:
    """HEAD the manifest and return the status code.

    Deliberately not `client.get_manifest`: that downloads the body and
    raises, where all we want here is the verdict. HEAD also does not count
    against the pull budget, which a GET would.
    """
    conn = http.client.HTTPSConnection(client.image.host, timeout=timeout, context=ssl_context())
    try:
        path = f"/v2/{repo}/manifests/{urllib.parse.quote(ref, safe=':@')}"
        conn.request(
            "HEAD",
            path,
            headers={
                "Authorization": f"Bearer {client.token}",
                "Accept": MANIFEST_ACCEPT,
                "User-Agent": USER_AGENT,
            },
        )
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        try:
            conn.close()
        except Exception:
            pass


def check_access(image_input: str, timeout: float = 30.0) -> AccessResult:
    """Decide whether one reference can be pulled, without pulling it.

    Two questions, in order, because they fail differently:

    1. Does the token grant any scope on this repo? No means private,
       deleted, or taken down, and no tag will help.
    2. Does the manifest exist for this tag? A repo can be perfectly
       public and simply not have the tag that was asked for.

    A missing `latest` is not a failure when the user never typed it: the
    puller falls back to the newest real tag, so this must agree with it
    or the preflight would reject images that download fine.
    """
    try:
        image = parse_image(image_input)
    except ValueError as exc:
        return AccessResult(image_input, status="error", detail=str(exc))

    client = RegistryClient(image, timeout=timeout)
    try:
        # Fetching the token is the first half of the answer: the registry
        # issues one to anyone, but its 'access' claim is empty when the repo
        # is not readable. Bind it so this reads as the deliberate request
        # it is rather than a stray attribute access.
        _token = client.token
        if not _token or not client._token_has_access():
            return AccessResult(
                image_input,
                status="inaccessible",
                detail=f"{image.repo} is private, deleted, or taken down",
            )

        status = _head_manifest(client, image.repo, image.ref, timeout)
        if status == 200:
            return AccessResult(image_input)
        if status in (401, 403):
            return AccessResult(
                image_input,
                status="inaccessible",
                detail=f"{image.repo} is private, deleted, or taken down (HTTP {status})",
            )
        if status == 429:
            return AccessResult(
                image_input,
                status="rate_limited",
                detail="registry rate limit reached",
            )
        if status == 404:
            if image.ref_implicit:
                # We invented ':latest'. The puller falls back to the newest
                # real tag, so the only thing that would make this image
                # unpullable is having no tags at all. Asking costs one more
                # request, and only on this branch.
                if client.list_tags():
                    return AccessResult(image_input)
                return AccessResult(
                    image_input,
                    status="missing_tag",
                    detail=f"{image.repo} has no tags at all",
                )
            tags = client.list_tags()
            return AccessResult(
                image_input,
                status="missing_tag",
                detail=f"{image.repo} has no tag {image.ref!r}",
                available_tags=tags,
            )
        return AccessResult(
            image_input, status="error", detail=f"unexpected HTTP {status} from registry"
        )
    except RateLimited as exc:
        return AccessResult(image_input, status="rate_limited", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - a preflight must never be fatal
        return AccessResult(image_input, status="error", detail=f"{type(exc).__name__}: {exc}")
    finally:
        client.close()


def check_many(
    images: Iterable[str],
    concurrency: int = 8,
    timeout: float = 30.0,
) -> list[AccessResult]:
    """Check a whole list, in input order.

    Order is preserved because the output is meant to be compared against
    the list the user wrote. Concurrency is worth more here than during
    the download, since every check is a short round trip and nothing is
    written to disk.
    """
    items = list(images)
    if not items:
        return []

    def one(ref: str) -> AccessResult:
        return check_access(ref, timeout=timeout)

    workers = max(1, min(concurrency, len(items)))
    if workers == 1:
        return [one(ref) for ref in items]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, items))


def summarize(results: list[AccessResult]) -> dict[str, int]:
    """Count results by status, always including the keys a caller expects.

    Reporting code should never have to guard against a missing key just
    because that failure did not happen this time.
    """
    counts = {key: 0 for key in REASONS}
    for res in results:
        counts[res.status] = counts.get(res.status, 0) + 1
    counts["total"] = len(results)
    counts["unavailable"] = len(results) - counts["ok"]
    return counts
