"""Registry HTTP client.

One token, one connection per thread, and a hard rule: never forward the
registry Authorization header to the CDN a blob redirect points at.
"""

import base64
import hashlib
import http.client
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

from .constants import CHUNK, DOCKERHUB_TOKEN_URL, ECR_PUBLIC_TOKEN_URL, MANIFEST_ACCEPT, USER_AGENT
from .ratelimit import registry_credentials
from .reference import ImageRef
from .tls import ssl_context


class RateLimited(RuntimeError):
    """The registry refused us for volume, not for permissions."""


class RetryableError(Exception):
    """An error worth another attempt, e.g. a dropped keep-alive socket."""


class RegistryClient:
    """Thin registry client with per-thread keep-alive connections."""

    retries = 3

    def __init__(self, image: ImageRef, timeout: float = 60.0):
        self.image = image
        self.timeout = timeout
        self._token: str | None = None
        self._local = threading.local()

    # -- auth ------------------------------------------------------------
    @property
    def token(self) -> str:
        if self._token is None:
            self._token = self._fetch_token()
        return self._token

    def _fetch_token(self) -> str:
        if self.image.registry == "dockerhub":
            url, service = DOCKERHUB_TOKEN_URL, "registry.docker.io"
        else:
            url, service = ECR_PUBLIC_TOKEN_URL, "public.ecr.aws"
        query = urllib.parse.urlencode(
            {"service": service, "scope": f"repository:{self.image.repo}:pull"}
        )
        headers = {"User-Agent": USER_AGENT}
        # Anonymous pulls are capped at 100 manifest requests per hour per IP,
        # which a batch of a few hundred images blows through. Credentials
        # raise that ceiling and also unlock private repos.
        creds = registry_credentials(self.image.registry)
        if creds:
            basic = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        req = urllib.request.Request(f"{url}?{query}", headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context()) as resp:
            data = json.load(resp)
        tok = data.get("token") or data.get("access_token") or ""
        if not tok:
            raise RuntimeError("registry returned no pull token")
        return tok

    # -- connections -----------------------------------------------------
    def _token_has_access(self) -> bool:
        """True if the current token grants any scope on this repo.

        The registry hands out a token to anyone, then returns 401 on the
        manifest when the repo is private or deleted. The token's own
        'access' claim already says so, which lets us fail fast with an
        accurate reason instead of retrying an answer that will not change.
        """
        token = self._token
        if not token or token.count(".") != 2:
            return True  # not a JWT we understand; let the request decide
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            return True
        return bool(claims.get("access"))

    def _conn(self) -> http.client.HTTPSConnection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = http.client.HTTPSConnection(
                self.image.host, timeout=self.timeout, context=ssl_context()
            )
            self._local.conn = conn
        return conn

    def _drop_conn(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _request(self, path: str, accept: str | None = None) -> http.client.HTTPResponse:
        """GET `path`, following registry redirects to blob storage."""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
        }
        if accept:
            headers["Accept"] = accept

        last_err: Exception | None = None
        refreshed = False
        for attempt in range(self.retries):
            try:
                conn = self._conn()
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()

                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.getheader("Location") or ""
                    resp.read()
                    return self._follow_redirect(location, accept)

                if resp.status == 404:
                    resp.read()
                    raise RuntimeError(f"not found: {self.image.repo}:{self.image.ref} ({path})")
                if resp.status in (401, 403):
                    resp.read()
                    # A stale token is worth one refresh. But an anonymous
                    # token with no granted scope means the repo is private
                    # or gone, and retrying just burns 12s per image, so say
                    # so immediately.
                    if refreshed or not self._token_has_access():
                        raise RuntimeError(
                            f"access denied: {self.image.repo} is private, "
                            f"deleted, or needs login (HTTP {resp.status})"
                        )
                    refreshed = True
                    self._token = None
                    headers["Authorization"] = f"Bearer {self.token}"
                    raise RetryableError(f"auth rejected with {resp.status}")
                if resp.status == 429:
                    # Rate limited. Retrying inside this request is pointless
                    # when the window is an hour, so surface it as its own
                    # error with the facts needed to act on it.
                    retry_after = resp.getheader("Retry-After") or ""
                    limit = resp.getheader("ratelimit-limit") or ""
                    resp.read()
                    hint = " (set DOCKERHUB_USERNAME/DOCKERHUB_TOKEN to raise it)"
                    raise RateLimited(
                        f"rate limited by {self.image.host}"
                        + (f", limit {limit}" if limit else "")
                        + (f", retry after {retry_after}s" if retry_after else "")
                        + (
                            hint
                            if self.image.registry == "dockerhub"
                            and not registry_credentials("dockerhub")
                            else ""
                        )
                    )
                if resp.status >= 400:
                    body = resp.read()[:200].decode("utf-8", "replace")
                    raise RetryableError(f"HTTP {resp.status} for {path}: {body}")
                return resp
            except RuntimeError:
                raise
            except (RetryableError, http.client.HTTPException, OSError) as exc:
                last_err = exc
                self._drop_conn()
                if attempt + 1 < self.retries:
                    time.sleep(0.4 * (2**attempt))
        raise RuntimeError(f"request failed after {self.retries} attempts: {path} ({last_err})")

    def _follow_redirect(self, location: str, accept: str | None):
        if not location:
            raise RuntimeError("redirect without Location header")
        # Blob redirects go to a signed CDN URL that must NOT carry our
        # registry Authorization header.
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        if accept:
            headers["Accept"] = accept
        if location.startswith("/"):
            location = f"https://{self.image.host}{location}"
        req = urllib.request.Request(location, headers=headers)
        return urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context())

    # -- typed helpers ---------------------------------------------------
    def get_manifest(self, reference: str) -> tuple[dict[str, Any], str]:
        path = f"/v2/{self.image.repo}/manifests/{urllib.parse.quote(reference, safe=':@')}"
        resp = self._request(path, accept=MANIFEST_ACCEPT)
        with resp:
            ctype = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip()
            return json.loads(resp.read().decode("utf-8")), ctype

    def list_tags(self) -> list[str]:
        """Tags for this repo via the standard /v2/ endpoint.

        Used to turn a bare 'not found' into an actionable message. Any
        failure here is non-fatal: this is diagnostics, not the main path.
        """
        try:
            resp = self._request(f"/v2/{self.image.repo}/tags/list?n=100")
            with resp:
                return list(json.loads(resp.read().decode("utf-8")).get("tags") or [])
        except Exception:
            return []

    def get_blob_json(self, digest: str) -> dict[str, Any]:
        resp = self._request(f"/v2/{self.image.repo}/blobs/{digest}")
        with resp:
            return json.loads(resp.read().decode("utf-8"))

    def download_blob(self, digest: str, dest: str, progress=None, verify: bool = True) -> str:
        """Download a blob, verifying it hashes to the digest the manifest promised.

        Without this check a corrupted or tampered layer extracts silently,
        which matters when the extracted tree is used for security scanning.
        """
        algo, _, expected = digest.partition(":")
        hasher = hashlib.new(algo) if verify and algo in hashlib.algorithms_available else None

        resp = self._request(f"/v2/{self.image.repo}/blobs/{digest}")
        with resp, open(dest, "wb") as out:
            while True:
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                if hasher is not None:
                    hasher.update(chunk)
                if progress:
                    progress(len(chunk))

        if hasher is not None and expected:
            actual = hasher.hexdigest()
            if actual != expected:
                try:
                    os.remove(dest)
                except OSError:
                    pass
                raise RuntimeError(
                    f"digest mismatch for {digest}: got {algo}:{actual} "
                    "(corrupted download or tampered blob)"
                )
        return dest

    def close(self) -> None:
        self._drop_conn()
