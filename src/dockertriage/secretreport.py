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
import re
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
#
# The generic buckets exist because the engines emit them in bulk: over 89
# images, `generic-api-key`, `URI` and `generic-password` alone were 46,000
# findings. Left in "other" they hid every named provider behind them.
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
    ("cdn-and-edge", ("cloudflare", "fastly", "akamai", "cloudfront")),
    ("observability", ("datadog", "sentry", "sonar", "airbrake", "newrelic", "sumologic")),
    ("connection-uris", ("uri", "url", "ftp", "connection")),
    ("generic-credentials", ("generic", "curl-auth", "basic-auth")),
)

# Path fragments that mark a finding as somebody else's code. Kept here as
# well as in the scanner because a report may be written from findings that
# were collected with `--include-vendor`, and a reader still wants them
# separated from the application's own leaks.
_VENDOR_HINTS = (
    "node_modules/",
    "site-packages/",
    "dist-packages/",
    "__pycache__/",
    ".venv/",
    "/venv/",
    "vendor/",
    "_cacache/",
    ".cache/",
    "bootsnap",
    "var/cache/",
    "var/lib/",
    "usr/share/doc/",
    "usr/share/man/",
    "APKINDEX",
    "ms-playwright/",
)


def _is_vendor_path(path: str) -> bool:
    """True when a finding comes from installed code rather than the app."""
    posix = path.replace(os.sep, "/")
    return any(hint in posix for hint in _VENDOR_HINTS)


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


_IMAGE_REPORT_FILES = {"SUMMARY.md", "INVENTORY.md", "findings.json", "env.json", "env.txt"}


def _copied_relpath(path: str) -> str:
    native = path.replace("/", os.sep)
    if os.path.dirname(native) == "" and os.path.basename(native) in _IMAGE_REPORT_FILES:
        return "files/" + path
    return path


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


def _source_file_paths(result: ScanResult) -> dict[str, dict[str, Any]]:
    """Files worth copying because they are credential files or hold findings."""
    paths: dict[str, dict[str, Any]] = {}
    for item in result.credential_files:
        path = str(item["path"])
        paths.setdefault(
            path,
            {
                "path": path,
                "bytes": item.get("bytes", ""),
                "reasons": [],
                "findings": 0,
                "rules": set(),
            },
        )["reasons"].append(str(item.get("reason", "credential file")))

    for finding in result.findings:
        if finding.source != "filesystem" or not finding.path or "!" in finding.path:
            continue
        if finding.severity not in {"critical", "high"} and finding.path not in paths:
            continue
        path = finding.path
        entry = paths.setdefault(
            path,
            {
                "path": path,
                "bytes": "",
                "reasons": [],
                "findings": 0,
                "rules": set(),
            },
        )
        entry["findings"] += 1
        entry["rules"].add(finding.rule)
    for entry in paths.values():
        if entry["findings"]:
            rules = ", ".join(sorted(entry["rules"]))
            entry["reasons"].append(f"contains {entry['findings']} finding(s): {rules}")
        entry["rules"] = sorted(entry["rules"])
        entry["reasons"] = sorted(set(entry["reasons"]))
    return paths


def _copy_source_files(folder: str, result: ScanResult) -> list[dict[str, Any]]:
    """Copy secret-bearing files under the image folder, preserving paths."""
    copied: list[dict[str, Any]] = []
    base = os.path.abspath(folder)
    for path, item in sorted(_source_file_paths(result).items()):
        native = path.replace("/", os.sep)
        source = os.path.join(result.root, native)
        if not os.path.isfile(source):
            continue
        target = os.path.abspath(os.path.join(folder, native))
        rel_target = path
        if not (target == base or target.startswith(base + os.sep)):
            continue
        rel_target = _copied_relpath(path)
        if rel_target != path:
            target = os.path.abspath(os.path.join(folder, rel_target.replace("/", os.sep)))
        try:
            _makedirs(os.path.dirname(target))
            shutil.copy2(source, target)
            os.chmod(target, _FILE_MODE)
            size = os.path.getsize(source)
            copied.append(
                {
                    "path": path,
                    "copied_to": rel_target.replace(os.sep, "/"),
                    "bytes": size,
                    "reasons": item["reasons"],
                    "findings": item["findings"],
                    "rules": item["rules"],
                }
            )
        except OSError:
            # The finding remains in findings.json; losing one convenience copy
            # must not fail the whole report.
            continue
    return copied


def _inventory_rows(items: list[dict[str, Any]]) -> list[str]:
    rows = [
        "| source path | copied to | reason | findings | bytes |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in items:
        reasons = "; ".join(item["reasons"]).replace("|", "\\|")
        rows.append(
            f"| `{item['path']}` | `{item['copied_to']}` | {reasons} | "
            f"{item['findings']} | {item['bytes']} |"
        )
    return rows


def _write_image_inventory(folder: str, result: ScanResult, copied: list[dict[str, Any]]) -> None:
    lines = [
        f"# Secret file inventory: {result.image}",
        "",
        "Files below were copied from the image filesystem with their original",
        "relative paths preserved under this folder.",
        "",
        f"- copied files: {len(copied)}",
        f"- findings: {len(result.findings)} ({_severity_line(result.by_severity())})",
        "",
    ]
    if copied:
        lines += ["## Copied files", "", *_inventory_rows(copied), ""]
    else:
        lines += ["## Copied files", "", "No filesystem files were copied for this image.", ""]
    _write(os.path.join(folder, "INVENTORY.md"), "\n".join(lines) + "\n")


def _write_by_image_inventory(base: str, scan: SecretScan) -> None:
    root = os.path.join(base, "by-image")
    _makedirs(root)
    lines = [
        "# By-image secret file inventory",
        "",
        "Each row points at the copied file under `by-image/<image>/`, with the",
        "image filesystem path preserved wherever it does not collide with report files.",
        "",
    ]
    rows = [
        "| image | source path | copied to | reason | findings | bytes |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    total = 0
    for result in scan.results:
        image_dir = _safe_name(result.image)
        for path, item in sorted(_source_file_paths(result).items()):
            source = os.path.join(result.root, path.replace("/", os.sep))
            if not os.path.isfile(source):
                continue
            copied_to = f"{image_dir}/{_copied_relpath(path)}"
            reasons = "; ".join(item["reasons"]).replace("|", "\\|")
            size = item["bytes"] or os.path.getsize(source)
            rows.append(
                f"| `{result.image}` | `{path}` | `{copied_to}` | {reasons} | "
                f"{item['findings']} | {size} |"
            )
            total += 1
    lines.append(f"- copied/source files listed: {total}")
    lines.append("")
    if total:
        lines += rows + [""]
    else:
        lines += ["No filesystem files were copied yet.", ""]
    _write(os.path.join(root, "INVENTORY.md"), "\n".join(lines) + "\n")


def _write_image_report(base: str, result: ScanResult) -> str:
    """One folder per image: findings, env, direct copies of source files."""
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

    copied = _copy_source_files(folder, result)
    _write_image_inventory(folder, result, copied)

    summary = [
        f"# {result.image}",
        "",
        f"- root: `{result.root}`",
        f"- findings: {len(result.findings)} ({_severity_line(result.by_severity())})",
        f"- copied source files: {len(copied)} (paths preserved under this image folder)",
        "",
    ]
    if result.findings:
        summary += ["## Findings", "", *_finding_rows(result.findings), ""]
    if result.credential_files:
        summary += ["## Credential files", ""]
        for item in result.credential_files:
            summary.append(f"- `{item['path']}` ({item['reason']}, {item['bytes']} bytes)")
        summary.append("")
    if copied:
        summary += ["## Copied source files", "", *_inventory_rows(copied), ""]
    summary += ["## Coverage", ""]
    summary += [f"- {line}" for line in result.coverage.lines()]
    if result.errors:
        summary += ["", "## Errors", ""] + [f"- {e}" for e in result.errors]
    _write(os.path.join(folder, "SUMMARY.md"), "\n".join(summary) + "\n")
    return folder


# A credential URI carries the secret plus whatever host it pointed at. One
# rotating-proxy password appeared under 143 distinct `user:pass@host:port`
# strings in a single file, which is 143 rows for one password to change.
# Grouping on the credential rather than the whole URI states the job as it
# will actually be done, with the hosts kept alongside as evidence.
_CREDENTIAL_URI = re.compile(
    r"^(?P<scheme>[a-z][\w+.-]*)://(?P<user>[^:/@\s]+):(?P<secret>[^@\s]+)@"
)


def _rotation_key(secret: str) -> str:
    """What actually has to be changed to make this secret useless.

    For a credential URI that is the password, not the endpoint it names.
    Everything else is its own rotation key.
    """
    match = _CREDENTIAL_URI.match(secret.strip())
    if match:
        return match.group("secret")
    return secret


def _group_by_secret(findings: list[Finding]) -> list[dict[str, Any]]:
    """Collapse findings to one entry per distinct credential.

    The same credential in 66 images is one thing to rotate, not 66. The
    places it appears become `occurrences`, because a responder still has to
    visit every one of them to remove it.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(_rotation_key(f.secret), []).append(f)

    out: list[dict[str, Any]] = []
    for key, items in groups.items():
        best = min(items, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        engines: set[str] = set()
        for f in items:
            engines.update(f.engine.split("+"))
        occurrences = [
            {
                "image": f.image,
                "path": f.path,
                "line": f.line,
                "source": f.source,
                "vendor": _is_vendor_path(f.path),
            }
            for f in sorted(items, key=lambda f: (f.image, f.path, f.line))
        ]
        variants = sorted({f.secret for f in items})
        entry = {
            "secret": key,
            "rule": best.rule,
            "description": best.description,
            "severity": best.severity,
            "engines": sorted(engines),
            "verified": any(f.verified for f in items) or None,
            # A secret found only inside installed packages is almost
            # always the package author's example, not this image's leak.
            "vendor": all(o["vendor"] for o in occurrences),
            "occurrence_count": len(items),
            "images": sorted({f.image for f in items if f.image}),
            "occurrences": occurrences,
        }
        if variants != [key]:
            # The endpoints this one credential was used against. Capped
            # because a rotating proxy list runs to hundreds of hosts.
            entry["variants"] = variants[:50]
            entry["variant_count"] = len(variants)
        out.append(entry)

    # Worst first, then the most widespread, because a key in 66 images is a
    # bigger job than the same severity in one.
    out.sort(
        key=lambda g: (
            SEVERITY_ORDER.get(g["severity"], 9),
            bool(g["vendor"]),
            -g["occurrence_count"],
            g["secret"],
        )
    )
    return out


def _secret_rows(groups: list[dict[str, Any]]) -> list[str]:
    """A markdown table of deduplicated secrets, values included."""
    rows = [
        "| severity | secret | rule | engines | occurrences | images | first seen |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for g in groups:
        secret = str(g["secret"]).replace("|", "\\|").replace("`", "'")
        secret = secret.replace("\n", " ").replace("\r", " ")
        if len(secret) > 120:
            secret = secret[:117] + "..."
        first = g["occurrences"][0]
        where = f"{first['image']}: {first['path']}" if first["image"] else first["path"]
        if first["line"]:
            where += f":{first['line']}"
        verified = " (verified live)" if g["verified"] else ""
        rows.append(
            f"| {g['severity']} | `{secret}` | {g['rule']}{verified} | "
            f"{', '.join(g['engines'])} | {g['occurrence_count']} | "
            f"{len(g['images'])} | {where} |"
        )
    return rows


def _write_by_type(base: str, findings: list[Finding]) -> None:
    """Group every finding by credential kind, for bulk rotation.

    One file per kind, deduplicated by secret, plus an index so the size of
    each bucket can be read without opening a 28 MB file.
    """
    buckets: dict[str, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(_kind_of(f), []).append(f)
    if not buckets:
        return
    root = os.path.join(base, "by-type")
    _makedirs(root)

    index: list[dict[str, Any]] = []
    for kind, items in sorted(buckets.items()):
        groups = _group_by_secret(items)
        app_groups = [g for g in groups if not g["vendor"]]
        vendor_groups = [g for g in groups if g["vendor"]]

        severity: dict[str, int] = {}
        for f in items:
            severity[f.severity] = severity.get(f.severity, 0) + 1
        rules: dict[str, set[str]] = {}
        for f in items:
            rules.setdefault(f.rule, set()).add(f.secret)
        rule_rows = sorted(
            ({"rule": r, "unique_secrets": len(s)} for r, s in rules.items()),
            key=lambda d: (-int(d["unique_secrets"]), str(d["rule"])),
        )

        totals = {
            "findings": len(items),
            "unique_secrets": len(groups),
            "images": len({f.image for f in items if f.image}),
            "by_severity": severity,
            "vendor_only_secrets": len(vendor_groups),
        }
        payload = {
            "kind": kind,
            "totals": totals,
            "rules": rule_rows,
            "secrets": groups,
        }
        _write(os.path.join(root, f"{kind}.json"), json.dumps(payload, indent=2))

        lines = [
            f"# {kind}",
            "",
            f"{len(groups)} unique secrets across {len(items)} findings "
            f"in {totals['images']} images.",
            f"Severity: {_severity_line(severity)}.",
            "",
            "## Rules",
            "",
            "| rule | unique secrets |",
            "| --- | --- |",
        ]
        lines += [f"| {r['rule']} | {r['unique_secrets']} |" for r in rule_rows]
        lines.append("")
        if app_groups:
            lines += ["## Secrets", "", *_secret_rows(app_groups), ""]
        if vendor_groups:
            lines += [
                "## Vendor-path only",
                "",
                "Every occurrence is inside installed packages or caches, so these",
                "are usually the package author's examples rather than this image's",
                "leak. Checked before dismissing, never deleted silently.",
                "",
                *_secret_rows(vendor_groups),
                "",
            ]
        _write(os.path.join(root, f"{kind}.md"), "\n".join(lines) + "\n")

        index.append(
            {
                "kind": kind,
                **totals,
                "json": f"{kind}.json",
                "markdown": f"{kind}.md",
            }
        )

    index.sort(key=lambda d: -int(d["unique_secrets"]))
    all_secrets = {f.secret for f in findings}
    _write(
        os.path.join(root, "index.json"),
        json.dumps(
            {
                "totals": {
                    "findings": len(findings),
                    "unique_secrets": len(all_secrets),
                    "kinds": len(index),
                    "images": len({f.image for f in findings if f.image}),
                },
                "kinds": index,
            },
            indent=2,
        ),
    )

    summary = [
        "# Findings by credential type",
        "",
        f"{len(all_secrets)} unique secrets across {len(findings)} findings.",
        "Rotate by reading one file per row: the unique-secret count is the",
        "size of the job, the finding count is how many places to edit.",
        "",
        "| kind | unique secrets | findings | images | critical | high | vendor-only |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in index:
        sev = row["by_severity"]
        summary.append(
            f"| [{row['kind']}]({row['markdown']}) | {row['unique_secrets']} | "
            f"{row['findings']} | {row['images']} | {sev.get('critical', 0)} | "
            f"{sev.get('high', 0)} | {row['vendor_only_secrets']} |"
        )
    summary.append("")
    _write(os.path.join(root, "SUMMARY.md"), "\n".join(summary) + "\n")


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
    if cov.excluded_file_count or cov.excluded_finding_count:
        lines += [
            "## Third-party trees, deliberately not searched",
            "",
            "Installed dependencies and package caches are somebody else's",
            "code. Measured over 89 images they produced 55% of all findings",
            "and not one that could be rotated: library docstrings, npm",
            "registry metadata, distribution checksums.",
            "",
            f"- {cov.excluded_file_count} paths pruned from the walk",
            f"- {cov.excluded_finding_count} engine findings dropped",
            "",
            "Re-run with `--include-vendor` to search them anyway.",
            "",
        ]
        if cov.excluded_paths:
            lines += ["By kind:", ""]
            lines += [
                f"- `{reason}`: {count} paths"
                for reason, count in sorted(cov.excluded_paths.items(), key=lambda kv: -kv[1])
            ]
            lines.append("")
        if cov.excluded_findings:
            lines += ["Findings dropped by reason:", ""]
            lines += [
                f"- `{reason}`: {count}"
                for reason, count in sorted(cov.excluded_findings.items(), key=lambda kv: -kv[1])
            ]
            lines.append("")
    if cov.complete:
        lines += ["Every engine ran and no path was skipped.", ""]
    _write(os.path.join(base, "UNSCANNED.md"), "\n".join(lines) + "\n")


def write_report(scan: SecretScan, out_dir: str, *, complete: bool = True) -> str:
    """Write the whole scan into `out_dir` and return its absolute path."""
    base = os.path.abspath(out_dir)
    _makedirs(base)

    findings = scan.findings
    counts = scan.by_severity()
    cov = scan.coverage()
    status = "complete" if complete else "in progress - only finished targets are included"

    _write(os.path.join(base, "findings.json"), json.dumps(scan.as_dict(), indent=2))

    for result in scan.results:
        _write_image_report(base, result)
    _write_by_image_inventory(base, scan)
    _write_by_type(base, findings)
    _write_unscanned(base, scan)

    lines = [
        "# Extracted secrets",
        "",
        "**Every value in this folder is a live credential in plaintext.**",
        "Treat the folder as the credentials themselves: do not commit it, do",
        "not attach it to a ticket, and delete it once the keys are rotated.",
        "",
        f"- status: {status}",
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
        lines.append("- `by-type/SUMMARY.md` - one row per credential kind, start here")
        lines.append("- `by-type/<kind>.json` - deduplicated by secret, with every occurrence")
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
    elif complete:
        lines += [
            "## No findings",
            "",
            "Read `UNSCANNED.md` before concluding the images are clean: an",
            "engine that was not installed reports nothing, which looks",
            "identical to finding nothing.",
            "",
        ]
    else:
        lines += [
            "## No findings yet",
            "",
            "The scan is still running. This report only includes targets that",
            "have finished so far.",
            "",
        ]

    lines += ["## Coverage", ""]
    lines += [f"- {line}" for line in cov.lines()]
    for note in cov.notes:
        lines.append(f"- {note}")
    lines.append("")

    _write(os.path.join(base, "SUMMARY.md"), "\n".join(lines) + "\n")
    marker = os.path.join(base, "IN_PROGRESS.md")
    if complete:
        try:
            os.unlink(marker)
        except FileNotFoundError:
            pass
    else:
        _write(
            marker,
            "# Scan in progress\n\n"
            "This folder is being updated after each target finishes. "
            "Open `findings.json`, `SUMMARY.md`, or `by-image/` to see "
            "completed work so far.\n",
        )
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
    if cov.excluded_finding_count:
        out.append(
            f"{cov.excluded_finding_count} findings in third-party trees set aside "
            f"(--include-vendor to keep them)"
        )
    out.append(f"written to {os.path.abspath(out_dir)}")
    return out


def top_findings(scan: SecretScan, limit: int = 10) -> list[Finding]:
    """The findings worth printing to the terminal immediately."""
    ranked = sorted(
        scan.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), not bool(f.verified)),
    )
    return ranked[:limit]
