"""Collect the credentials inside an extracted image into one place.

Detection is bought, not built. Measured against a 17-secret corpus,
betterleaks found 11, gitleaks 9, detect-secrets 11, and TruffleHog 5, so
this module runs the installed engines and merges them rather than shipping
a rival rule set that would need maintaining against every new token format.

Two gaps in that measurement are ours to close, and they are the reason this
module contains any detection at all:

* a credential named only by its variable. `DB_PASSWORD=hunter2` has no
  shape for a pattern to match, and every engine missed it. The name is the
  evidence, so a value under a secret-shaped name is reported as one.
* a credential file whose contents look unremarkable. An `.npmrc` token was
  missed by all three Go engines; `.aws/credentials`, keystores and private
  keys are found by name here whatever an engine makes of the bytes.

The other half of the job is honesty about coverage. A scanner that skips
quietly produces the same empty report as a clean image, so every engine
that did not run, and every file nothing read, is recorded and surfaced.

Stdlib only, like every module except the CLI.
"""

import dataclasses
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from .constants import IMAGE_META_NAME, LAYER_CACHE_NAME

__all__ = [
    "ENGINES",
    "Engine",
    "Finding",
    "ScanCoverage",
    "ScanResult",
    "available_engines",
    "credential_file_reason",
    "discover_targets",
    "select_engines",
    "is_commented_out",
    "merge_findings",
    "noise_reason",
    "scan_image_config",
    "scan_tree_for_secrets",
    "secret_env_findings",
]

# Our own bookkeeping, which is not part of the image's filesystem. The
# record is read deliberately for its config, not walked as a source file.
_SELF_SKIP = {LAYER_CACHE_NAME}

# Ordering for reports: the finding that gets someone paged goes first.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclasses.dataclass
class Finding:
    """One credential, with enough context to act on without rescanning.

    `secret` holds the value in the clear. The point of the report is
    immediate rotation, and you cannot rotate what you cannot identify.
    """

    rule: str
    description: str
    severity: str
    secret: str
    path: str
    source: str = "filesystem"
    line: int = 0
    context: str = ""
    engine: str = "dockertriage"
    verified: bool | None = None
    image: str = ""
    # What the engine said about its own match. Kept because `confidence`
    # answers "how sure was the regex" while `severity` answers "what does
    # this unlock", and a responder wants both.
    confidence: str = ""
    entropy: float = 0.0
    # betterleaks' stable id for a finding, which survives re-runs and so
    # lets one report be diffed against the next.
    fingerprint: str = ""
    # The source line, when the engine returned it. Avoids re-reading the
    # file to decide whether the credential is commented out.
    line_text: str = ""

    @property
    def key(self) -> tuple[str, str, int]:
        """Identity for merging: same secret, same place, one finding.

        Deliberately not keyed on rule or engine, so two engines reporting
        the same leak collapse into one. The same password reused in two
        files stays two findings, because both have to be fixed.

        A path inside an archive collapses onto the archive itself, because
        one engine reads `bundle.tar.gz!inner/config.js` while another sees
        only `bundle.tar.gz`. They are the same leak in the same file.
        """
        return (self.secret, self.path.split("!", 1)[0], self.line)

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
            "secret": self.secret,
            "path": self.path,
            "source": self.source,
            "engine": self.engine,
        }
        if self.image:
            d["image"] = self.image
        if self.line:
            d["line"] = self.line
        if self.context:
            d["context"] = self.context
        if self.verified is not None:
            d["verified"] = self.verified
        if self.confidence:
            d["confidence"] = self.confidence
        if self.entropy:
            d["entropy"] = round(self.entropy, 4)
        if self.fingerprint:
            d["fingerprint"] = self.fingerprint
        return d


@dataclasses.dataclass
class ScanCoverage:
    """What was examined, and what was not, so "clean" can be believed.

    Engines that were not installed are the largest blind spot, because
    their absence looks identical to them finding nothing.
    """

    files_seen: int = 0
    bytes_seen: int = 0
    engines_run: list[str] = dataclasses.field(default_factory=list)
    engines_missing: list[str] = dataclasses.field(default_factory=list)
    engines_failed: list[dict[str, str]] = dataclasses.field(default_factory=list)
    unscanned: list[dict[str, str]] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)
    # Third-party trees deliberately not searched, counted by kind. A count
    # rather than a path list: there are tens of thousands of them, and what
    # a reader needs is the scale of what was set aside, not its inventory.
    excluded_paths: dict[str, int] = dataclasses.field(default_factory=dict)
    excluded_findings: dict[str, int] = dataclasses.field(default_factory=dict)

    # Enough to act on without turning the report into a second filesystem.
    _MAX_NAMED = 500

    def note_unscanned(self, path: str, reason: str) -> None:
        if len(self.unscanned) < self._MAX_NAMED:
            self.unscanned.append({"path": path, "reason": reason})

    def note_excluded_path(self, reason: str) -> None:
        """One more file skipped because it belongs to somebody else."""
        self.excluded_paths[reason] = self.excluded_paths.get(reason, 0) + 1

    def note_excluded_finding(self, reason: str) -> None:
        """One more engine finding dropped because of where it came from."""
        self.excluded_findings[reason] = self.excluded_findings.get(reason, 0) + 1

    @property
    def excluded_file_count(self) -> int:
        return sum(self.excluded_paths.values())

    @property
    def excluded_finding_count(self) -> int:
        return sum(self.excluded_findings.values())

    @property
    def complete(self) -> bool:
        """True when every engine ran and nothing was left unread."""
        return not (self.engines_missing or self.engines_failed or self.unscanned)

    def merge(self, other: ScanCoverage) -> None:
        self.files_seen += other.files_seen
        self.bytes_seen += other.bytes_seen
        for name in other.engines_run:
            if name not in self.engines_run:
                self.engines_run.append(name)
        for name in other.engines_missing:
            if name not in self.engines_missing:
                self.engines_missing.append(name)
        for item in other.engines_failed:
            if item not in self.engines_failed:
                self.engines_failed.append(item)
        for item in other.unscanned:
            self.note_unscanned(item["path"], item["reason"])
        for reason, count in other.excluded_paths.items():
            self.excluded_paths[reason] = self.excluded_paths.get(reason, 0) + count
        for reason, count in other.excluded_findings.items():
            self.excluded_findings[reason] = self.excluded_findings.get(reason, 0) + count
        for note in other.notes:
            if note not in self.notes:
                self.notes.append(note)

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_seen": self.files_seen,
            "bytes_seen": self.bytes_seen,
            "engines_run": list(self.engines_run),
            "engines_missing": list(self.engines_missing),
            "engines_failed": list(self.engines_failed),
            "complete": self.complete,
            "unscanned": list(self.unscanned),
            "excluded_file_count": self.excluded_file_count,
            "excluded_finding_count": self.excluded_finding_count,
            "excluded_paths": dict(self.excluded_paths),
            "excluded_findings": dict(self.excluded_findings),
            "notes": list(self.notes),
        }

    def lines(self) -> list[str]:
        """Human summary of coverage, one claim per line."""
        out = [f"{self.files_seen} files ({self.bytes_seen} bytes) offered to the engines"]
        if self.engines_run:
            out.append(f"engines run: {', '.join(self.engines_run)}")
        if self.engines_missing:
            out.append(
                f"NOT INSTALLED, so their rules never ran: {', '.join(self.engines_missing)}"
            )
        for failure in self.engines_failed:
            out.append(f"engine {failure['engine']} failed: {failure['error']}")
        if self.unscanned:
            out.append(f"{len(self.unscanned)} paths recorded as unscanned")
        if self.excluded_file_count:
            kinds = ", ".join(
                f"{reason} ({count})"
                for reason, count in sorted(self.excluded_paths.items(), key=lambda kv: -kv[1])[:6]
            )
            out.append(
                f"{self.excluded_file_count} files in third-party trees were not searched: {kinds}"
            )
        if self.excluded_finding_count:
            out.append(
                f"{self.excluded_finding_count} engine findings dropped as third-party noise"
            )
        if self.complete:
            out.append("every engine ran and no path was skipped")
        return out


@dataclasses.dataclass
class ScanResult:
    """Everything one target yielded, plus proof of what was covered."""

    image: str
    root: str
    findings: list[Finding] = dataclasses.field(default_factory=list)
    coverage: ScanCoverage = dataclasses.field(default_factory=ScanCoverage)
    credential_files: list[dict[str, str]] = dataclasses.field(default_factory=list)
    env: list[dict[str, str]] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {
            "image": self.image,
            "root": os.path.abspath(self.root),
            "finding_count": len(self.findings),
            "by_severity": self.by_severity(),
            "findings": [f.as_dict() for f in self.findings],
            "credential_files": list(self.credential_files),
            "env": list(self.env),
            "coverage": self.coverage.as_dict(),
            "errors": list(self.errors),
        }


# ---------------------------------------------------------------------------
# Engines. Each adapter turns one tool's output into our Finding shape.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Engine:
    """One external scanner: how to find it, run it, and read its output."""

    name: str
    binary: str
    install_hint: str
    # Measured recall on the 17-secret corpus, recorded so the ranking in the
    # report reflects evidence rather than reputation.
    measured_recall: str = ""

    def available(self) -> str | None:
        return shutil.which(self.binary)


BETTERLEAKS = Engine(
    "betterleaks",
    "betterleaks",
    "brew install betterleaks",
    "11/17 on the reference corpus, the strongest single engine measured",
)
GITLEAKS = Engine(
    "gitleaks",
    "gitleaks",
    "brew install gitleaks",
    "9/17, superseded by betterleaks; only used when betterleaks is absent",
)
TRUFFLEHOG = Engine(
    "trufflehog",
    "trufflehog",
    "brew install trufflehog",
    "5/17, a second opinion with its own rule set",
)

ENGINES = [BETTERLEAKS, GITLEAKS, TRUFFLEHOG]

# betterleaks is the maintained continuation of gitleaks: same rule family,
# a superset of the flags, and measured higher on the reference corpus
# (11/17 against 9/17). Running both costs a second full walk of the tree to
# re-derive nearly the same findings, so gitleaks is a stand-in for when
# betterleaks is not installed rather than a peer.
_SUPERSEDED = {GITLEAKS.name: BETTERLEAKS.name}


def available_engines() -> tuple[list[Engine], list[Engine]]:
    """Split the known engines into installed and missing."""
    present = [e for e in ENGINES if e.available()]
    missing = [e for e in ENGINES if not e.available()]
    return present, missing


def select_engines(engines: list[Engine]) -> tuple[list[Engine], list[str]]:
    """Drop an engine when the tool that replaced it is also installed.

    Returns the engines to run and a note for each one stood down, because
    an engine that silently did not run is the failure mode this module
    exists to prevent.
    """
    installed = {e.name for e in engines if e.available()}
    keep: list[Engine] = []
    notes: list[str] = []
    for engine in engines:
        replacement = _SUPERSEDED.get(engine.name)
        if replacement and replacement in installed:
            notes.append(
                f"{engine.name} was not run: {replacement} supersedes it "
                f"(same rules, measured higher), and both would scan the same tree twice"
            )
            continue
        keep.append(engine)
    return keep, notes


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv list, never a shell string
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


# betterleaks and gitleaks share an output schema, so one adapter reads both.
def _read_leaks_json(raw: str, engine: str, root: str, image: str) -> list[Finding]:
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    out: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        secret = str(item.get("Secret") or item.get("Match") or "").strip()
        if not secret:
            continue
        path = str(item.get("File") or "")
        # Engines report paths relative to where they were invoked; make them
        # relative to the image root so findings from different engines and
        # different runs line up.
        path = _relativise(path, root)
        rule = str(item.get("RuleID") or "unknown")
        attributes = item.get("Attributes")
        confidence = ""
        if isinstance(attributes, dict):
            confidence = str(attributes.get("confidence") or "")
        # betterleaks returns the surrounding source line under --match-context.
        # Preferring it over `Match` means a commented-out credential can be
        # recognised from the engine's own output, with no second read.
        line_text = str(item.get("MatchContext") or "")
        out.append(
            Finding(
                rule=rule,
                description=str(item.get("Description") or rule),
                severity=_severity_for(rule, attributes),
                secret=secret,
                path=path,
                line=int(item.get("StartLine") or 0),
                context=(line_text or str(item.get("Match") or ""))[:200],
                engine=engine,
                image=image,
                source=_source_for(path),
                verified=_validation_state(item),
                confidence=confidence,
                entropy=float(item.get("Entropy") or 0.0),
                fingerprint=str(item.get("Fingerprint") or ""),
                line_text=line_text,
            )
        )
    return out


def _validation_state(item: dict[str, Any]) -> bool | None:
    """Read betterleaks' --validation verdict, if it ran.

    Only a proven-live credential is True and a proven-dead one False;
    everything else stays None, because "we did not check" and "we checked
    and it is dead" are different claims.
    """
    for key in ("ValidationStatus", "Validation", "Status"):
        raw = item.get(key)
        if isinstance(raw, dict):
            raw = raw.get("status") or raw.get("Status")
        if not raw:
            continue
        state = str(raw).strip().lower()
        if state == "valid":
            return True
        if state in {"invalid", "revoked"}:
            return False
    return None


def _read_trufflehog_json(raw: str, root: str, image: str) -> list[Finding]:
    """TruffleHog emits one JSON object per line, not a JSON array."""
    out: list[Finding] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        secret = str(item.get("Raw") or "").strip()
        if not secret:
            continue
        meta = ((item.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        path = _relativise(str(meta.get("file") or ""), root)
        detector = str(item.get("DetectorName") or "unknown")
        out.append(
            Finding(
                rule=detector,
                description=str(item.get("DetectorDescription") or detector),
                # A verified credential is not a maybe: it was used against
                # the live service and worked.
                severity="critical" if item.get("Verified") else "high",
                secret=secret,
                path=path,
                line=int(meta.get("line") or 0),
                engine="trufflehog",
                verified=bool(item.get("Verified")),
                image=image,
                source=_source_for(path),
            )
        )
    return out


def _relativise(path: str, root: str) -> str:
    """Express an engine's path relative to the scanned root.

    Always forward-slashed, matching `_iter_files`, so the same file gets
    the same name whichever source reported it and whichever OS ran it.
    """
    if not path:
        return ""
    absolute = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    if absolute.startswith(root_abs + os.sep):
        return os.path.relpath(absolute, root_abs).replace(os.sep, "/")
    # Engines invoked with a relative target echo it back verbatim.
    base = os.path.basename(root_abs)
    normalised = path.replace(os.sep, "/")
    marker = base + "/"
    if marker in normalised:
        return normalised.split(marker, 1)[1]
    return normalised


def _source_for(path: str) -> str:
    """Whether a finding came from the image config or from the filesystem."""
    return "image-config" if os.path.basename(path) == IMAGE_META_NAME else "filesystem"


# Rule ids whose names alone establish the blast radius. Engines rank by
# confidence in a match; we rank by what the credential unlocks.
_CRITICAL_RULE = re.compile(
    r"(aws|gcp|azure|private[-_]?key|stripe|github|gitlab|slack|npm|pypi|"
    r"sendgrid|twilio|openai|anthropic|credential[-_]?uri|service[-_]?account)",
    re.IGNORECASE,
)


def _severity_for(rule: str, attributes: Any) -> str:
    if _CRITICAL_RULE.search(rule):
        return "critical"
    if isinstance(attributes, dict):
        confidence = str(attributes.get("confidence") or "").lower()
        if confidence == "low":
            return "medium"
    return "high"


# betterleaks does several things gitleaks cannot, and each one closes a gap
# this module previously worked around or reported as a permanent limitation.
#
#   --max-archive-depth  reads inside tar/zip/whl. 500 archives were recorded
#                        as "contents unexamined" in the last full run; a
#                        Stripe live key inside a .tar.gz proved findable.
#   --max-decode-depth   decodes base64 before matching. The `ghs_` GitHub
#                        tokens in `.git/config` are base64 inside an
#                        `AUTHORIZATION: basic` header and were invisible.
#   --match-context      returns the source line with the finding, so a
#                        commented-out credential can be told from a live one
#                        without re-reading every implicated file.
#
# Deliberately not used: --confidence. Measured on one real image it cut 215
# findings to 59 at `medium`, but among the dropped was a live Google OAuth
# client secret. Severity here is about what a credential unlocks, not how
# sure the regex was, so the filtering happens on our side where a miss is
# visible.
_ARCHIVE_DEPTH = "8"
_DECODE_DEPTH = "5"
_MATCH_CONTEXT = "1L"


def _betterleaks_flags(verify: bool) -> list[str]:
    """The betterleaks-only flags, each closing a measured gap."""
    flags = [
        "--max-archive-depth",
        _ARCHIVE_DEPTH,
        "--max-decode-depth",
        _DECODE_DEPTH,
        "--match-context",
        _MATCH_CONTEXT,
    ]
    if verify:
        # Same contract as TruffleHog's: only ever on an explicit request,
        # because it sends candidate credentials to the provider's API.
        flags.append("--validation")
    return flags


def run_engine(
    engine: Engine, root: str, image: str, timeout: float, verify: bool
) -> tuple[list[Finding], str | None]:
    """Run one engine over `root`. Returns (findings, error message)."""
    binary = engine.available()
    if not binary:
        return [], f"{engine.name} is not installed"

    try:
        if engine.name in {"betterleaks", "gitleaks"}:
            # Report to stdout via '-', so nothing is written next to the
            # image being scanned.
            cmd = [
                binary,
                "dir",
                root,
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--no-banner",
                "--exit-code",
                "0",
            ]
            if engine.name == "betterleaks":
                cmd += _betterleaks_flags(verify)
            proc = _run(cmd, timeout)
            return _read_leaks_json(proc.stdout, engine.name, root, image), None

        if engine.name == "trufflehog":
            cmd = [binary, "filesystem", root, "--json", "--no-update"]
            if not verify:
                # Verification sends candidate credentials to third-party
                # APIs. That is a deliberate act, never a side effect.
                cmd.append("--no-verification")
            proc = _run(cmd, timeout)
            return _read_trufflehog_json(proc.stdout, root, image), None
    except subprocess.TimeoutExpired:
        return [], f"{engine.name} timed out after {timeout:.0f}s"
    except OSError as exc:
        return [], f"{engine.name} could not run: {exc}"
    return [], f"no adapter for {engine.name}"


# ---------------------------------------------------------------------------
# The gap the engines leave: credentials identified by name, not by shape.
# ---------------------------------------------------------------------------

# Variable names that declare a credential outright. A value under one of
# these is a finding whatever it looks like, which is what every engine
# missed on `DB_PASSWORD=hunter2`.
_SECRET_NAME = re.compile(
    r"(?:PASSWORD|PASSWD|^PWD$|SECRET|TOKEN|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|"
    r"PRIVATE[_-]?KEY|CREDENTIAL|SESSION[_-]?KEY|ENCRYPTION[_-]?KEY|"
    r"CLIENT[_-]?SECRET|AUTH[_-]?TOKEN|DATABASE[_-]?URL|DB[_-]?URL|DSN|"
    r"CONNECTION[_-]?STRING)",
    re.IGNORECASE,
)

# Values that match the name rule but mean "fill this in". Reporting them
# buries the real findings, which is its own way of losing a secret.
#
# The second group was added after a measured run: `admin`, `root`, `wstoken`
# and `abc12345` accounted for 612 findings across the corpus, and not one
# of them was a credential anybody could rotate.
_PLACEHOLDER = re.compile(
    r"^(?:"
    r"x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|"
    r"change[_-]?me|changeit|placeholder|example|sample|dummy|test|testing|"
    r"test[_-]?purpose|testpurpose|"
    r"your[_-]?\w*|my[_-]?\w*|some[_-]?\w*|insert[_-]?\w*|todo|fixme|"
    r"none|null|nil|true|false|undefined|empty|unset|"
    r"password|passwd|secret|token|apikey|api[_-]?key|"
    r"admin|root|user|username|guest|default|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"dev|devel|development|staging|stage|prod|production|local|"
    r"abc\d{3,}|123\d*|foo|bar|baz|qwerty|"
    r"\w*token|\w*secret|\w*password"  # bare wstoken / mysecret style names
    r"|\$[\{(]?\w+[\})]?|%\w+%|<[^>]*>|\{\{[^}]*\}\}"
    r")$",
    re.IGNORECASE,
)

# Values that are a path or a URL without credentials in it. `DATABASE_URL`
# matches the name rule, but `file:/data/app.db` is not a secret, and real
# images set exactly that.
_NOT_A_SECRET = re.compile(
    r"^(?:"
    r"file:.*|"
    r"/[\w./-]*|"
    r"(?:https?|redis|mongodb|postgres(?:ql)?|mysql|amqp)://"
    r"(?![^\s/@]+:[^\s/@]+@)[^\s]*"  # a URL with no user:pass@ in it
    r")$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    if not stripped or len(stripped) < 4:
        return True
    return bool(_PLACEHOLDER.match(stripped)) or bool(_NOT_A_SECRET.match(stripped))


def secret_env_findings(name: str, value: str, path: str, image: str, source: str) -> list[Finding]:
    """Report a value whose variable name declares it a credential.

    This is the measured gap. Engines match shapes, so `SECRET_KEY=hunter2`
    is invisible to them while being exactly what this command exists for.
    """
    if not value or not _SECRET_NAME.search(name) or _is_placeholder(value):
        return []
    return [
        Finding(
            rule="named-secret-variable",
            description=f"{name} names a credential, and it has a value",
            severity="critical",
            secret=value,
            path=path,
            source=source,
            context=f"{name}={value}"[:200],
            image=image,
        )
    ]


def scan_image_config(
    record: dict[str, Any], image: str
) -> tuple[list[Finding], list[dict[str, str]]]:
    """Read the half of an image that is configuration rather than files.

    `ENV DB_PASSWORD=...` is baked into the image config. Engines that walk
    the rootfs see `.image.json` as an ordinary JSON file, so they catch the
    shaped values in it and miss the named ones. This closes that.
    """
    findings: list[Finding] = []
    listing: list[dict[str, str]] = []
    config = record.get("config")
    if not isinstance(config, dict):
        return findings, listing

    where = f"{IMAGE_META_NAME} (config.Env)"
    for raw in config.get("Env") or []:
        if not isinstance(raw, str) or "=" not in raw:
            continue
        name, _, value = raw.partition("=")
        if not value:
            continue
        listing.append({"name": name, "value": value})
        findings.extend(secret_env_findings(name, value, where, image, "image-config"))

    # Credentials get passed as command flags more often than anyone admits.
    for field in ("Cmd", "Entrypoint"):
        argv = config.get(field)
        if not isinstance(argv, list):
            continue
        for arg in argv:
            text = str(arg)
            if "=" not in text:
                continue
            flag, _, value = text.partition("=")
            findings.extend(
                secret_env_findings(
                    flag.lstrip("-"),
                    value,
                    f"{IMAGE_META_NAME} (config.{field})",
                    image,
                    "image-config",
                )
            )
    return findings, listing


# ---------------------------------------------------------------------------
# The other gap: files that are credentials by name, whatever is inside them.
# ---------------------------------------------------------------------------

_CREDENTIAL_NAMES = {
    ".env": "environment file",
    ".envrc": "direnv environment file",
    ".netrc": "netrc login file",
    "_netrc": "netrc login file",
    ".npmrc": "npm registry token file",
    ".pypirc": "PyPI upload credentials",
    ".git-credentials": "stored git credentials",
    ".dockercfg": "docker registry credentials",
    "credentials": "cloud or service credentials file",
    "id_rsa": "private SSH key",
    "id_dsa": "private SSH key",
    "id_ecdsa": "private SSH key",
    "id_ed25519": "private SSH key",
    "kubeconfig": "kubernetes credentials",
    ".bash_history": "shell history, often holds pasted credentials",
    ".zsh_history": "shell history, often holds pasted credentials",
    ".mysql_history": "database shell history",
    ".psql_history": "database shell history",
    "secrets.yaml": "secrets manifest",
    "secrets.yml": "secrets manifest",
    "service-account.json": "service account key",
}

_CREDENTIAL_SUFFIXES = (
    (".pem", "PEM key or certificate"),
    (".key", "private key"),
    (".p12", "PKCS#12 keystore"),
    (".pfx", "PKCS#12 keystore"),
    (".jks", "Java keystore"),
    (".keystore", "Java keystore"),
    (".kdbx", "KeePass database"),
    (".ovpn", "OpenVPN profile, may embed keys"),
)

# Archives hide files no engine opened. Recorded so "nothing found" is never
# confused with "we did not look".
_ARCHIVE_EXT = {
    ".zip",
    ".jar",
    ".war",
    ".ear",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".whl",
    ".egg",
    ".apk",
    ".deb",
    ".rpm",
    ".zst",
}


# ---------------------------------------------------------------------------
# Noise. Measured on a 89-image corpus of 64,599 findings: 55% of them came
# from directories that hold somebody else's code or the package manager's
# bookkeeping, and every sample checked was a docstring, a fixture or a
# checksum rather than a credential this image leaked.
#
# `pydantic/networks.py` documents `http://samuel:pass@example.com:8000`.
# `_cacache` stores npm registry metadata whose dist-tags look like API keys.
# `APKINDEX` is a list of package digests. None of these can be rotated, and
# reporting them buries the `.env` file three screens further down.
#
# Excluded paths are counted, not discarded silently: the count reaches the
# report, so the difference between "nothing there" and "we did not look"
# survives, which is the rule the rest of this module is built on.
# ---------------------------------------------------------------------------

# Directory names that mean "this is not our code". Matched on any path
# segment, because a vendored tree can sit at any depth.
_VENDOR_DIRS = {
    "node_modules": "installed npm package",
    "bower_components": "installed bower package",
    "site-packages": "installed python package",
    "dist-packages": "installed python package",
    "__pycache__": "compiled python bytecode",
    ".venv": "python virtualenv",
    "venv": "python virtualenv",
    "virtualenv": "python virtualenv",
    "vendor": "vendored dependency tree",
    "gems": "installed ruby gem",
    "bundle": "installed ruby bundle",
    "pkg/mod": "go module cache",
    ".cargo": "rust crate cache",
    ".nuget": "nuget package cache",
    ".m2": "maven repository",
    ".gradle": "gradle cache",
    "ms-playwright": "playwright browser bundle",
    "site_perl": "installed perl module",
}

# Package-manager and build caches. Content-addressed blobs and compiled
# artefacts: high entropy by construction, so every engine lights up.
_CACHE_DIRS = {
    "_cacache": "npm content-addressed cache",
    ".npm": "npm cache",
    "bootsnap": "bootsnap compile cache",
}

# Path fragments, checked as substrings, for caches that need two segments
# to identify and for OS package metadata.
_NOISE_FRAGMENTS = (
    (".cache/yarn", "yarn cache"),
    (".cache/pip", "pip cache"),
    (".cache/node", "node cache"),
    (".cache/ms-playwright", "playwright cache"),
    (".cache/bootsnap", "bootsnap compile cache"),
    (".bun/install", "bun install cache"),
    (".next/cache", "next.js build cache"),
    ("tmp/cache", "framework cache"),
    ("var/cache/apk", "alpine package cache"),
    ("var/cache/apt", "debian package cache"),
    ("var/lib/apt", "debian package database"),
    ("var/lib/dpkg", "dpkg database"),
    ("lib/apk/db", "alpine package database"),
    ("usr/share/doc", "distribution documentation"),
    ("usr/share/man", "manual pages"),
    ("usr/share/locale", "locale data"),
    ("usr/share/info", "info pages"),
    ("usr/share/perl", "perl standard library"),
    ("usr/lib/perl", "perl standard library"),
    ("usr/share/tcltk", "tcl/tk standard library"),
    ("usr/share/gconf", "gconf schema data"),
    ("APKINDEX", "alpine package index"),
)


def noise_reason(relpath: str) -> str:
    """Why this path holds somebody else's code, or '' if it is ours.

    Returning a reason rather than a bool so the report can say which kind
    of noise was skipped, and how much of it.
    """
    # betterleaks names a file inside an archive `bundle.tar.gz!inner/x`.
    # Both halves are judged: a vendored tarball is noise, and so is a
    # `node_modules` that only exists inside one.
    posix = relpath.replace(os.sep, "/")
    for segment in posix.split("!"):
        found = _noise_reason_for(segment)
        if found:
            return found
    return ""


def _noise_reason_for(posix: str) -> str:
    parts = posix.split("/")
    for part in parts:
        reason = _VENDOR_DIRS.get(part) or _CACHE_DIRS.get(part)
        if reason:
            return reason
    lowered = posix.lower()
    for fragment, reason in _NOISE_FRAGMENTS:
        if fragment.lower() in lowered:
            return reason
    # `pkg/mod` is two segments, so it cannot be matched above.
    if "/pkg/mod/" in f"/{posix}/":
        return "go module cache"
    return ""


def credential_file_reason(relpath: str) -> str:
    """Why this filename is a credential by nature, or '' if it is not."""
    name = os.path.basename(relpath).lower()
    parts = relpath.replace(os.sep, "/").lower().split("/")

    if name in _CREDENTIAL_NAMES:
        return _CREDENTIAL_NAMES[name]
    if name.startswith(".env."):
        return "environment file"
    for suffix, why in _CREDENTIAL_SUFFIXES:
        if name.endswith(suffix):
            return why
    if ".aws" in parts and name in {"config", "credentials"}:
        return "AWS credentials file"
    if ".ssh" in parts and name.startswith("id_"):
        return "private SSH key"
    if ".docker" in parts and name == "config.json":
        return "docker registry credentials"
    return ""


def _iter_files(
    root: str,
    exclude: Callable[[str], str] | None = None,
    on_excluded: Callable[[str], None] | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield (absolute, relative) for every regular file under `root`.

    The relative path always uses forward slashes, so a report written on
    Windows names the same file as one written on Linux. Engines report
    POSIX-style paths too, which is what lets findings from different
    sources merge instead of appearing twice.

    Symlinks are never followed: a link to `/` would otherwise walk the host
    filesystem, and a link's target inside the tree is visited on its own.

    `exclude` returns a reason to skip a path, or '' to keep it. Directories
    are pruned whole, so a `node_modules` holding 40,000 files costs one
    check rather than 40,000, and `on_excluded` sees the reason so the
    report can say how much was set aside and why.
    """
    stack = [(root, True)]
    while stack:
        current, is_root = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            if is_root and entry.name in _SELF_SKIP:
                continue
            try:
                if entry.is_symlink():
                    continue
                rel = os.path.relpath(entry.path, root).replace(os.sep, "/")
                if exclude is not None:
                    why = exclude(rel)
                    if why:
                        if on_excluded is not None:
                            on_excluded(why)
                        continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append((entry.path, False))
                elif entry.is_file(follow_symlinks=False):
                    yield entry.path, rel
            except OSError:
                continue


def _scan_env_file(absolute: str, rel: str, image: str) -> list[Finding]:
    """Read an env-style file for named credentials the engines skip."""
    try:
        with open(absolute, encoding="utf-8", errors="replace") as fh:
            text = fh.read(512 * 1024)
    except OSError:
        return []
    out: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip().removeprefix("export ").strip()
        value = value.strip().strip("\"'")
        for finding in secret_env_findings(name, value, rel, image, "filesystem"):
            finding.line = number
            out.append(finding)
    return out


# Line prefixes that mean the code on this line does not run. A credential
# on a commented line is disabled history, not a live leak: measured at 653
# findings (3.6%) across the corpus, including whole blocks of rotated-out
# tokens kept "just in case".
_COMMENT_PREFIX = re.compile(r"^\s*(?:#|//|;|--|\*|/\*|<!--|%|rem\s)", re.IGNORECASE)


def is_commented_out(line: str, secret: str) -> bool:
    """True when `secret` sits on a line that a parser would ignore.

    Requires the secret to actually appear on the line, so a comment that
    merely precedes real code cannot suppress a finding underneath it.
    """
    if not line or not _COMMENT_PREFIX.match(line):
        return False
    probe = secret[:24]
    return bool(probe) and probe in line


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates, keeping the strongest claim about each secret.

    A verified credential beats an unverified one, and a critical beats a
    high, because the merged report is what someone triages from.
    """
    best: dict[tuple[str, str, int], Finding] = {}
    engines: dict[tuple[str, str, int], set[str]] = {}
    for f in findings:
        engines.setdefault(f.key, set()).add(f.engine)
        current = best.get(f.key)
        if current is None:
            best[f.key] = f
            continue
        if f.verified is True and current.verified is not True:
            best[f.key] = f
        elif SEVERITY_ORDER.get(f.severity, 9) < SEVERITY_ORDER.get(current.severity, 9):
            best[f.key] = f
        elif len(f.path) > len(current.path) and f.path.startswith(current.path):
            # `bundle.tar.gz!inner/config.js` names the file the credential
            # is actually in; `bundle.tar.gz` only names the container.
            best[f.key] = f
    out = []
    for key, finding in best.items():
        # Agreement between independent engines is signal worth keeping.
        names = sorted(engines[key])
        if len(names) > 1:
            finding.engine = "+".join(names)
        out.append(finding)
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line, f.secret))
    return out


def scan_tree_for_secrets(
    root: str,
    image: str = "",
    engines: list[Engine] | None = None,
    timeout: float = 600.0,
    verify: bool = False,
    include_vendor: bool = False,
    extra_excludes: Iterable[str] = (),
) -> ScanResult:
    """Scan one extracted image, or any directory, for credentials.

    Runs every installed engine, adds the two classes of finding they were
    measured to miss, and records what did not run so an empty report can be
    told apart from an unexamined one.

    By default the installed-dependency trees are left alone: measured over
    89 images, they produced 55% of all findings and none that could be
    rotated. `include_vendor` scans them anyway; either way the count of
    what was set aside reaches the report.
    """
    root = os.path.abspath(root)
    result = ScanResult(image=image or os.path.basename(root), root=root)
    cov = result.coverage
    collected: list[Finding] = []

    extra = tuple(e.strip().strip("/") for e in extra_excludes if e and e.strip())

    # Decided before the walk, because it changes what the walk records about
    # archives: betterleaks reads inside them, so calling them unexamined
    # when it is running would understate coverage.
    planned, _ = select_engines(engines if engines is not None else ENGINES)
    archives_covered = any(e.name == "betterleaks" and e.available() for e in planned)

    def excluded_because(rel: str) -> str:
        """Why this path is out of scope, or '' if it is in scope."""
        if include_vendor:
            builtin = ""
        else:
            builtin = noise_reason(rel)
        if builtin:
            return builtin
        posix = rel.replace(os.sep, "/")
        segments = posix.split("/")
        for pattern in extra:
            if pattern in segments or posix.startswith(pattern + "/") or posix == pattern:
                return f"excluded by --exclude {pattern}"
        return ""

    # The image config half: read deliberately, because it is configuration
    # rather than a file the engines would interpret as one.
    record_path = os.path.join(root, IMAGE_META_NAME)
    if os.path.isfile(record_path):
        try:
            with open(record_path, encoding="utf-8") as fh:
                record = json.load(fh)
            if isinstance(record, dict):
                if record.get("image"):
                    result.image = str(record["image"])
                config_findings, listing = scan_image_config(record, result.image)
                collected.extend(config_findings)
                result.env = listing
        except (OSError, ValueError) as exc:
            result.errors.append(f"could not read {IMAGE_META_NAME}: {exc}")

    # The filesystem half: credential files by name, env files by content,
    # and a note for every archive nothing opened.
    for absolute, rel in _iter_files(root, excluded_because, cov.note_excluded_path):
        cov.files_seen += 1
        try:
            size = os.path.getsize(absolute)
        except OSError as exc:
            cov.note_unscanned(rel, f"unreadable: {exc}")
            continue
        cov.bytes_seen += size

        why = credential_file_reason(rel)
        if why:
            result.credential_files.append({"path": rel, "reason": why, "bytes": str(size)})

        if os.path.splitext(rel)[1].lower() in _ARCHIVE_EXT:
            # betterleaks unpacks archives itself, so only say the contents
            # went unread when the engine that reads them is not running.
            if not archives_covered:
                cov.note_unscanned(rel, "archive: no engine unpacks it, contents unexamined")
            continue

        name = os.path.basename(rel).lower()
        if (
            name.startswith(".env")
            or name in {".envrc", ".npmrc", ".netrc"}
            or why.endswith("environment file")
        ):
            collected.extend(_scan_env_file(absolute, rel, result.image))

    # The engines. Absence is recorded rather than tolerated silently: an
    # uninstalled scanner and a clean image produce the same empty list.
    selected = engines if engines is not None else ENGINES
    selected, superseded = select_engines(selected)
    cov.notes.extend(superseded)
    for engine in selected:
        if not engine.available():
            cov.engines_missing.append(engine.name)
            continue
        found, error = run_engine(engine, root, result.image, timeout, verify)
        if error:
            cov.engines_failed.append({"engine": engine.name, "error": error})
            continue
        cov.engines_run.append(engine.name)
        collected.extend(found)

    # Engines walk the tree themselves, so pruning our own walk does not stop
    # them reporting from a vendored directory. Drop those here, by the same
    # rule, and count them so the report stays honest about the difference.
    kept: list[Finding] = []
    for finding in collected:
        if finding.source == "filesystem":
            why = excluded_because(finding.path)
            if why:
                cov.note_excluded_finding(why)
                continue
        kept.append(finding)
    collected = kept

    # A credential on a commented-out line is disabled history. Checked
    # against the file rather than guessed, so a secret that merely sits
    # near a comment is still reported.
    collected = _drop_commented_out(collected, root, cov)

    if not cov.engines_run:
        cov.notes.append(
            "No external engine ran. Only name-based detection was applied, "
            "which finds credential files and named variables but not tokens "
            "recognised by shape. Install betterleaks for full coverage."
        )
    if verify and cov.engines_run:
        cov.notes.append(
            f"Live verification was enabled for {', '.join(cov.engines_run)}: "
            f"candidate credentials were sent to their providers' APIs."
        )

    result.findings = merge_findings(collected)
    return result


def _drop_commented_out(findings: list[Finding], root: str, cov: ScanCoverage) -> list[Finding]:
    """Remove findings whose line is commented out in the real file.

    betterleaks returns the source line with `--match-context`, so most
    findings are decided without touching the disk. Anything without one
    falls back to reading the file, each read at most once.
    """
    out: list[Finding] = []
    needs_read: dict[str, list[Finding]] = {}

    for f in findings:
        if f.line_text:
            if is_commented_out(f.line_text, f.secret):
                cov.note_excluded_finding("commented-out code")
                continue
            out.append(f)
        elif f.source == "filesystem" and f.line:
            needs_read.setdefault(f.path, []).append(f)
        else:
            out.append(f)

    for rel, group in needs_read.items():
        lines: list[str] | None = None
        try:
            with open(os.path.join(root, rel.replace("/", os.sep)), "rb") as fh:
                lines = fh.read(8 * 1024 * 1024).decode("utf-8", "replace").splitlines()
        except OSError:
            # An unreadable file is not evidence that the secret is disabled.
            lines = None
        for f in group:
            if lines is not None and 1 <= f.line <= len(lines):
                if is_commented_out(lines[f.line - 1], f.secret):
                    cov.note_excluded_finding("commented-out code")
                    continue
            out.append(f)
    return out


def discover_targets(path: str) -> list[str]:
    """Decide what `dt secrets <path>` should scan.

    Three shapes are all reasonable to point at, and guessing wrong either
    misses images or scans one tree as if it were many:

    * an extracted image, recognised by its `.image.json`
    * a parent of extracted images, the usual `output/` from a batch
    * any other directory, scanned whole, which is what `dt secrets .` means
      when the working directory is a checkout rather than a pull
    """
    root = os.path.abspath(path)
    if os.path.isfile(os.path.join(root, IMAGE_META_NAME)):
        return [root]

    children = []
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        return [root]
    for entry in entries:
        if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):
            continue
        if os.path.isfile(os.path.join(entry.path, IMAGE_META_NAME)):
            children.append(entry.path)
    # Only treat it as a parent when it actually holds images; otherwise the
    # directory is the target, so a plain source tree still gets scanned.
    return children or [root]


@dataclasses.dataclass
class SecretScan:
    """A whole run: one or many images, with totals for the report."""

    results: list[ScanResult] = dataclasses.field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def coverage(self) -> ScanCoverage:
        total = ScanCoverage()
        for r in self.results:
            total.merge(r.coverage)
        return total

    @property
    def affected(self) -> list[ScanResult]:
        return [r for r in self.results if r.findings]

    def as_dict(self) -> dict[str, Any]:
        return {
            "images_scanned": len(self.results),
            "images_with_findings": len(self.affected),
            "finding_count": len(self.findings),
            "by_severity": self.by_severity(),
            "coverage": self.coverage().as_dict(),
            "results": [r.as_dict() for r in self.results],
        }
