"""A verifying TLS context that still works when Python ships no CA bundle.

Some standalone CPython builds - notably the python-build-standalone
distributions that ``uv`` and ``pipx`` install on macOS - do not bundle a
certificate file and do not read the system keychain. On those,
``ssl.create_default_context()`` trusts nothing, so every registry request
fails with ``CERTIFICATE_VERIFY_FAILED``.

We build the normal default context first (which honours ``SSL_CERT_FILE`` and
``SSL_CERT_DIR``). If it ended up with an empty trust store, we load the first
system CA bundle we can find. Verification stays on either way; we never fall
back to trusting everything.
"""

import ssl

# Well-known locations of a system CA bundle, most specific first. macOS and
# Homebrew come first because that is where the gap actually bites; the Linux
# distro paths let a slim container with a trimmed Python keep working too.
_CA_BUNDLE_CANDIDATES = (
    "/etc/ssl/cert.pem",  # macOS (LibreSSL), several BSDs
    "/opt/homebrew/etc/ca-certificates/cert.pem",  # Homebrew, Apple Silicon
    "/usr/local/etc/ca-certificates/cert.pem",  # Homebrew, Intel
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora, RHEL, CentOS
    "/etc/ssl/ca-bundle.pem",  # openSUSE
)

# The context is immutable once built, so build it once and reuse it.
_context: ssl.SSLContext | None = None


def _ca_count(ctx: ssl.SSLContext) -> int:
    """Number of CA certificates the context currently trusts."""
    return ctx.cert_store_stats().get("x509_ca", 0)


def ssl_context() -> ssl.SSLContext:
    """Return a cached, certificate-verifying TLS context.

    Falls back to a system CA bundle only when the default context loaded no
    certificates, so a CA-less Python install verifies certificates instead of
    failing outright.
    """
    global _context
    if _context is not None:
        return _context

    ctx = ssl.create_default_context()
    if _ca_count(ctx) == 0:
        for path in _CA_BUNDLE_CANDIDATES:
            try:
                ctx.load_verify_locations(cafile=path)
            except OSError, ssl.SSLError:
                continue  # missing or unreadable bundle; try the next one
            if _ca_count(ctx) > 0:
                break

    _context = ctx
    return ctx
