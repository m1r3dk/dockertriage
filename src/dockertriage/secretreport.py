"""Write a scan out as a folder someone can act on.

The output is deliberately a directory rather than a single file. A JSON
report answers "what was found", but responding to a leak also needs the
offending files themselves (to see the surrounding code), the secrets
grouped by kind (to rotate an entire class at once), and a statement of what
was not examined (to know how far the "clean" verdict reaches).

Every value is written in the clear. The folder is a concentrated credential
dump, so it is created with owner-only permissions and the summary says so.

Stdlib only, like every module except the CLI.
"""

import json
import os
import shutil
from typing import Any

from .secrets import SEVERITY_ORDER, Finding, ScanResult, SecretScan

__all__ = ["DEFAULT_OUTPUT_DIR", "write_report"]

# Created in the working directory unless -o says otherwise, so a scan never
# writes into the image being scanned.
DEFAULT_OUTPUT_DIR = "extracted_secrets"

# Owner-only. The folder holds live credentials in plaintext.
_DIR_MODE = 0o700
_FILE_MODE = 0o600

# Findings are grouped into these buckets so a responder can rotate one class
# of credential at a time. Matched against the rule id, in order.
_KIND_RULES = (
    ("aws", ("aws",)),
    ("gcp", ("gcp", "google", "service-account", "service_account")),
    ("azure", ("azure",)),
    ("private-keys", ("private-key", "private_key", "privatekey", "ssh", "pgp")),
    ("database", ("postgres", "mysql", "mongo", "redis", "database", "db-url", "credential-uri")),
    ("payment", ("stripe", "paypal", "square", "braintree")),
    ("source-control", ("github", "gitlab", "bitbucket")),
    ("package-registry", ("npm", "pypi", "rubygems", "nuget", "artifactory")),
    ("messaging", ("slack", "discord", "telegram", "twilio", "sendgrid", "mailgun", "smtp")),
    ("ai-provider", ("openai", "anthropic", "huggingface", "cohere")),
    ("jwt-and-sessions", ("jwt", "session", "cookie")),
    ("named-variables", ("named-secret-variable",)),
)


def _kind_of(finding: Finding) -> str:
    """Which rotation bucket a finding belongs in."""
    rule = finding.rule.lower()
    for kind, needles in _KIND_RULES:
        if any(needle in rule for needle in needles):
            return kind
    return "other"


def _safe_name(text: str) -> str:
    """A filesystem-safe folder name for an image reference."""
    out = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in text)
    return out.strip("_") or "image"


def _write(path: str, content: str) -> None:
    """Write a file owner-readable only, since these hold live credentials."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    try:
        os.chmod(path, _FILE_MODE)
    except OSError:
        # A filesystem without permission bits is not a reason to lose the
        # report; the summary still warns about what the folder contains.
        pass


def _makedirs(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, _DIR_MODE)
    except OSError:
        pass


def _severity_line(counts: dict[str, int]) -> str:
    parts = [
        f"{counts[name]} {name}"
        for name in ("critical", "high", "medium", "low")
        if counts.get(name)
    ]
    return ", ".join(parts) if parts else "none"


def _finding_rows(findings: list[Finding]) -> list[str]:
    """A markdown table of findings, secrets included."""
    rows = [
        "| severity | secret | where | rule | engine |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        where = f.path + (f":{f.line}" if f.line else "")
        # Pipes and backticks would break the table; a secret is shown
        # verbatim inside code markers so whitespace stays visible.
        secret = f.secret.replace("|", "\\|").replace("`", "'")
        if len(secret) > 120:
            secret = secret[:117] + "..."
        verified = " (verified live)" if f.verified else ""
        rows.append(f"| {f.severity} | `{secret}` | {where} | {f.rule}{verified} | {f.engine} |")
    return rows


def _write_image_report(base: str, result: ScanResult) -> str:
    """One folder per image: findings, env, copies of credential files."""
    folder = os.path.join(base, "by-image", _safe_name(result.image))
    _makedirs(folder)

    _write(folder + os.sep + "findings.json", json.dumps(result.as_dict(), indent=2))

    if result.env:
        # The full environment, not only the flagged entries: a responder
        # reading one variable usually wants to see its neighbours.
        _write(
            os.path.join(folder, "env.json"),
            json.dumps(result.env, indent=2),
        )
        lines = [f"{item['name']}={item['value']}" for item in result.env]
        _write(os.path.join(folder, "env.txt"), "\n".join(lines) + "\n")

    # Copy the credential-bearing files themselves. A finding names a line;
    # responding to it usually means reading what is around that line.
    copied = 0
    if result.credential_files:
        files_dir = os.path.join(folder, "files")
        _makedirs(files_dir)
        for item in result.credential_files:
            # Findings carry forward-slashed paths so reports match across
            # platforms; turn them back into real paths to copy the files.
            native = item["path"].replace("/", os.sep)
            source = os.path.join(result.root, native)
            target = os.path.join(files_dir, native)
            try:
                _makedirs(os.path.dirname(target))
                shutil.copy2(source, target)
                os.chmod(target, _FILE_MODE)
                copied += 1
            except OSError:
                # A file that cannot be copied is still reported as a
                # finding; losing the copy must not lose the report.
                continue

    summary = [
        f"# {result.image}",
        "",
        f"- root: `{result.root}`",
        f"- findings: {len(result.findings)} ({_severity_line(result.by_severity())})",
        f"- credential files: {len(result.credential_files)} ({copied} copied into `files/`)",
        "",
    ]
    if result.findings:
        summary += ["## Findings", "", *_finding_rows(result.findings), ""]
    if result.credential_files:
        summary += ["## Credential files", ""]
        for item in result.credential_files:
            summary.append(f"- `{item['path']}` ({item['reason']}, {item['bytes']} bytes)")
        summary.append("")
    summary += ["## Coverage", ""]
    summary += [f"- {line}" for line in result.coverage.lines()]
    if result.errors:
        summary += ["", "## Errors", ""] + [f"- {e}" for e in result.errors]
    _write(os.path.join(folder, "SUMMARY.md"), "\n".join(summary) + "\n")
    return folder


def _write_by_type(base: str, findings: list[Finding]) -> None:
    """Group every finding by credential kind, for bulk rotation."""
    buckets: dict[str, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(_kind_of(f), []).append(f)
    if not buckets:
        return
    root = os.path.join(base, "by-type")
    _makedirs(root)
    for kind, items in sorted(buckets.items()):
        items.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.image, f.path))
        _write(
            os.path.join(root, f"{kind}.json"),
            json.dumps([f.as_dict() for f in items], indent=2),
        )
        lines = [f"# {kind}", "", f"{len(items)} findings.", ""]
        for f in items:
            where = f"{f.image}: {f.path}" + (f":{f.line}" if f.line else "")
            lines.append(f"- `{f.secret}`  ({where})")
        _write(os.path.join(root, f"{kind}.md"), "\n".join(lines) + "\n")


def _write_unscanned(base: str, scan: SecretScan) -> None:
    """Say plainly what nothing looked at, so "clean" can be read correctly."""
    cov = scan.coverage()
    lines = [
        "# What was not scanned",
        "",
        "A scanner that skips quietly produces the same empty report as a",
        "clean image. Everything below was **not** examined, so no finding",
        "from it could have been reported either way.",
        "",
    ]
    if cov.engines_missing:
        lines += [
            "## Engines that never ran",
            "",
            "These are not installed, so none of their rules were applied:",
            "",
        ]
        lines += [f"- **{name}**" for name in cov.engines_missing]
        lines.append("")
    if cov.engines_failed:
        lines += ["## Engines that failed", ""]
        lines += [f"- **{f['engine']}**: {f['error']}" for f in cov.engines_failed]
        lines.append("")
    if cov.unscanned:
        lines += [
            "## Paths not examined",
            "",
            f"{len(cov.unscanned)} recorded (archives are the usual case: no",
            "engine unpacks them, so a credential inside one is invisible).",
            "",
        ]
        lines += [f"- `{item['path']}` - {item['reason']}" for item in cov.unscanned]
        lines.append("")
    if cov.complete:
        lines += ["Every engine ran and no path was skipped.", ""]
    _write(os.path.join(base, "UNSCANNED.md"), "\n".join(lines) + "\n")


def write_report(scan: SecretScan, out_dir: str) -> str:
    """Write the whole scan into `out_dir` and return its absolute path."""
    base = os.path.abspath(out_dir)
    _makedirs(base)

    findings = scan.findings
    counts = scan.by_severity()
    cov = scan.coverage()

    _write(os.path.join(base, "findings.json"), json.dumps(scan.as_dict(), indent=2))

    for result in scan.results:
        _write_image_report(base, result)
    _write_by_type(base, findings)
    _write_unscanned(base, scan)

    lines = [
        "# Extracted secrets",
        "",
        "**Every value in this folder is a live credential in plaintext.**",
        "Treat the folder as the credentials themselves: do not commit it, do",
        "not attach it to a ticket, and delete it once the keys are rotated.",
        "",
        "## Totals",
        "",
        f"- images scanned: {len(scan.results)}",
        f"- images with findings: {len(scan.affected)}",
        f"- findings: {len(findings)} ({_severity_line(counts)})",
        f"- engines run: {', '.join(cov.engines_run) or 'none'}",
    ]
    if cov.engines_missing:
        lines.append(
            f"- **not installed, so their rules never ran**: {', '.join(cov.engines_missing)}"
        )
    lines += ["", "## Where to look", "", "- `findings.json` - everything, machine-readable"]
    if scan.affected:
        lines.append("- `by-image/<image>/` - per image, with copies of the offending files")
    if findings:
        lines.append("- `by-type/` - grouped by credential kind, for bulk rotation")
    lines.append("- `UNSCANNED.md` - what nothing looked at, and why")
    lines.append("")

    if findings:
        worst = [f for f in findings if f.severity == "critical"][:50]
        if worst:
            lines += [
                "## Critical findings",
                "",
                *_finding_rows(worst),
                "",
            ]
        by_image: dict[str, int] = {}
        for f in findings:
            by_image[f.image] = by_image.get(f.image, 0) + 1
        lines += ["## Findings per image", ""]
        for image, count in sorted(by_image.items(), key=lambda kv: -kv[1]):
            lines.append(f"- {image}: {count}")
        lines.append("")
    else:
        lines += [
            "## No findings",
            "",
            "Read `UNSCANNED.md` before concluding the images are clean: an",
            "engine that was not installed reports nothing, which looks",
            "identical to finding nothing.",
            "",
        ]

    lines += ["## Coverage", ""]
    lines += [f"- {line}" for line in cov.lines()]
    for note in cov.notes:
        lines.append(f"- {note}")
    lines.append("")

    _write(os.path.join(base, "SUMMARY.md"), "\n".join(lines) + "\n")
    return base


def summary_lines(scan: SecretScan, out_dir: str) -> list[str]:
    """What the CLI prints when the scan finishes."""
    counts = scan.by_severity()
    cov = scan.coverage()
    out = [
        f"{len(scan.findings)} findings ({_severity_line(counts)}) "
        f"in {len(scan.affected)}/{len(scan.results)} images",
    ]
    if cov.engines_run:
        out.append(f"engines: {', '.join(cov.engines_run)}")
    if cov.engines_missing:
        out.append(f"not installed, so their rules never ran: {', '.join(cov.engines_missing)}")
    if cov.unscanned:
        out.append(f"{len(cov.unscanned)} paths unscanned, listed in UNSCANNED.md")
    out.append(f"written to {os.path.abspath(out_dir)}")
    return out


def top_findings(scan: SecretScan, limit: int = 10) -> list[Finding]:
    """The findings worth printing to the terminal immediately."""
    ranked = sorted(
        scan.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), not bool(f.verified)),
    )
    return ranked[:limit]


def as_report_dict(scan: SecretScan) -> dict[str, Any]:
    return scan.as_dict()
