"""Docker Hub pull budget.

Reading the budget before a batch turns "it died halfway through" into a
warning printed before any work starts.
"""

import base64
import dataclasses
import http.client
import json
import os
import urllib.parse
import urllib.request

from .constants import DOCKERHUB_REGISTRY, DOCKERHUB_TOKEN_URL, USER_AGENT
from .tls import ssl_context


@dataclasses.dataclass
class RateBudget:
    """What Docker Hub will let this caller do right now."""

    limit: int | None = None
    remaining: int | None = None
    window_seconds: int | None = None
    authenticated: bool = False

    @property
    def known(self) -> bool:
        return self.remaining is not None

    def describe(self) -> str:
        who = "authenticated" if self.authenticated else "anonymous"
        if not self.known:
            return f"rate limit unknown ({who})"
        window = ""
        if self.window_seconds:
            hours = self.window_seconds / 3600
            window = f" per {hours:.0f}h" if hours >= 1 else f" per {self.window_seconds}s"
        return f"{self.remaining}/{self.limit} pulls left{window} ({who})"


def _parse_rate_header(value: str | None) -> tuple[int | None, int | None]:
    """Parse '100;w=21600' into (100, 21600)."""
    if not value:
        return None, None
    head, _, rest = value.partition(";")
    try:
        count = int(head.strip())
    except ValueError:
        return None, None
    window = None
    if "w=" in rest:
        try:
            window = int(rest.split("w=", 1)[1].split(",")[0].strip())
        except ValueError:
            window = None
    return count, window


def check_rate_budget(timeout: float = 15.0) -> RateBudget:
    """Ask Docker Hub how many pulls we have left, without spending one.

    Uses the ratelimitpreview image and a HEAD request, which the registry
    documents as the way to check a budget without consuming it. Any failure
    returns an empty budget: this informs the user, it must never block work.
    """
    creds = registry_credentials("dockerhub")
    budget = RateBudget(authenticated=bool(creds))
    try:
        query = urllib.parse.urlencode(
            {"service": "registry.docker.io", "scope": "repository:ratelimitpreview/test:pull"}
        )
        headers = {"User-Agent": USER_AGENT}
        if creds:
            basic = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        req = urllib.request.Request(f"{DOCKERHUB_TOKEN_URL}?{query}", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as resp:
            token = json.load(resp).get("token", "")
        if not token:
            return budget
        conn = http.client.HTTPSConnection(
            DOCKERHUB_REGISTRY, timeout=timeout, context=ssl_context()
        )
        try:
            conn.request(
                "HEAD",
                "/v2/ratelimitpreview/test/manifests/latest",
                headers={"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT},
            )
            resp = conn.getresponse()
            resp.read()
            limit, window = _parse_rate_header(resp.getheader("ratelimit-limit"))
            remaining, _ = _parse_rate_header(resp.getheader("ratelimit-remaining"))
            budget.limit, budget.window_seconds, budget.remaining = limit, window, remaining
            if resp.status == 429:
                budget.remaining = 0
        finally:
            conn.close()
    except Exception:
        return budget
    return budget


def registry_credentials(registry: str) -> tuple[str, str] | None:
    """Credentials from the environment, if the user supplied any.

    Deliberately env-only: reading ~/.docker/config.json would drag in
    credential-helper binaries, and this tool's promise is that it runs
    anywhere with nothing installed.
    """
    if registry != "dockerhub":
        return None
    user = os.environ.get("DOCKERHUB_USERNAME") or os.environ.get("DOCKER_USERNAME")
    secret = (
        os.environ.get("DOCKERHUB_TOKEN")
        or os.environ.get("DOCKERHUB_PASSWORD")
        or os.environ.get("DOCKER_PASSWORD")
    )
    return (user, secret) if user and secret else None
