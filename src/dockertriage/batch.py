"""Pull many images without letting one failure end the run.

A bad reference in a list of 500 must not abandon the other 499, so every
failure is recorded as data. A rate limit is the one exception: it will hit
every remaining image, so the batch stops instead of digging deeper.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import preflight, puller, ratelimit
from . import verify as verify_mod
from .constants import SKIPPED_FILE_NAME
from .errors import RateLimited
from .ratelimit import RateBudget, registry_credentials

__all__ = ["BatchResult", "pull_many", "read_image_list"]


def read_image_list(path: str) -> list[str]:
    """Read image references from a file, one per line.

    Tolerates what real lists actually contain: blank lines, '#' comments,
    inline trailing comments, surrounding quotes and commas (people paste
    from JSON/CSV), and duplicates. Order is preserved because a triage run
    should be reproducible. Use '-' to read stdin.
    """
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()

    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Strip an inline comment, but only when clearly separated, so we
        # never truncate a legitimate '#' inside a reference.
        for marker in ("  #", "\t#"):
            if marker in line:
                line = line.split(marker, 1)[0].strip()
        line = line.strip("\"'").rstrip(",").strip().strip("\"'")
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


@dataclasses.dataclass
class BatchResult:
    """Outcome of one image in a batch. Failures are data, not exceptions."""

    image: str
    dest: str | None = None
    error: str | None = None
    seconds: float = 0.0
    # Filled in by the post-pull check: None when verification was skipped,
    # otherwise the reason the folder on disk is or is not trustworthy.
    verified: bool | None = None
    verify_status: str | None = None
    verify_problems: list[str] = dataclasses.field(default_factory=list)
    # How the verdict was reached, e.g. "5/5 checks passed (quick)", plus the
    # individual checks for a report.
    verify_summary: str | None = None
    verify_checks: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    # Set when the preflight decided this image could not be pulled at all,
    # e.g. 'inaccessible' or 'missing_tag'. None means it was attempted.
    access_status: str | None = None

    @property
    def skipped(self) -> bool:
        """True when the image was never attempted because it was unreachable."""
        return self.access_status is not None

    @property
    def ok(self) -> bool:
        """True only when the pull succeeded and the folder survived the check.

        A pull that reported success but left an unverifiable folder is a
        failure: the whole point of asking is to not have to trust the log.
        """
        return self.error is None and self.verified is not False

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"image": self.image, "ok": self.ok, "seconds": round(self.seconds, 2)}
        if self.dest:
            d["dest"] = self.dest
        if self.error:
            d["error"] = self.error
        if self.access_status:
            d["access_status"] = self.access_status
            d["skipped"] = True
        if self.verified is not None:
            d["verified"] = self.verified
            d["verify_status"] = self.verify_status
            if self.verify_summary:
                d["verify_summary"] = self.verify_summary
            if self.verify_checks:
                d["verify_checks"] = list(self.verify_checks)
            if self.verify_problems:
                d["verify_problems"] = list(self.verify_problems)
        return d


def pull_many(
    images: Iterable[str],
    out_dir: str,
    jobs: int = 8,
    os_name: str = "linux",
    arch: str = "amd64",
    keep_tar: bool = False,
    quiet: bool = False,
    verify: bool = True,
    concurrency: int = 1,
    stop_on_error: bool = False,
    strict_tag: bool = False,
    check_budget: bool = True,
    verify_pulls: bool = True,
    deep_verify: bool = False,
    check_access: bool = True,
    on_result=None,
) -> list[BatchResult]:
    """Pull every image in `images`, isolating failures.

    One bad reference in a list of 500 must not abandon the other 499, so
    each pull is wrapped and recorded. `concurrency` controls how many
    images are in flight; each still uses `jobs` threads internally, so the
    real worst case is concurrency * jobs sockets.

    `check_access` asks the registry which references are reachable before
    downloading anything, so a list's dead entries are known up front as a
    count rather than discovered one at a time. The probe costs no pull
    budget. Unreachable images are recorded as skipped, never attempted.

    Every image that pulls is then checked against what landed on disk, so
    the final tally is a statement about the filesystem rather than about
    what the code believed it did. `deep_verify` re-counts the whole tree
    instead of trusting the census the pull just took.
    """
    items = list(images)
    results: list[BatchResult] = []
    if not items:
        return results

    width = len(str(len(items)))
    counter = [0]
    lock = threading.Lock()

    def log(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr, flush=True)

    # Check the budget before spending it. Finding out mid-run that the list
    # was always too big is the failure mode this avoids.
    try:
        budget = ratelimit.check_rate_budget() if check_budget else RateBudget()
    except Exception:
        # Diagnostics must never be the reason a batch does not start.
        budget = RateBudget()
    remaining = budget.remaining
    if remaining is not None:
        log(f"docker hub: {budget.describe()}")
        if remaining == 0:
            log("  none left; the window must reset before any pull succeeds")
            if not budget.authenticated:
                log("  set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN to raise the limit")
        elif remaining < len(items):
            log(
                f"  {len(items)} images but only {remaining} pulls left: "
                f"expect to stop around image {remaining}"
            )
            if not budget.authenticated:
                log("  set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN to raise the limit")

    rate_limited = threading.Event()

    # Preflight: find out which references the registry will actually serve
    # before spending time and bandwidth discovering it one at a time. This
    # costs no pull budget, so it is worth doing over the whole list.
    unreachable: list[BatchResult] = []
    if check_access and len(items) > 1:
        log(f"checking access for {len(items)} images (no pull budget used)...")
        t_pre = time.time()
        access = preflight.check_many(items, concurrency=max(8, concurrency))
        counts = preflight.summarize(access)
        pullable = [a.image for a in access if a.ok]
        log(
            f"  {counts['ok']}/{counts['total']} accessible, "
            f"{counts['unavailable']} not ({time.time() - t_pre:.1f}s)"
        )
        for key, label in (
            ("inaccessible", "private, deleted, or taken down"),
            ("missing_tag", "tag does not exist"),
            ("error", "could not be checked"),
            ("rate_limited", "rate limited before checking"),
        ):
            if counts.get(key):
                log(f"    {counts[key]} {label}")
        # Record the unreachable ones as results so they appear in the
        # report and the tally, rather than silently vanishing from a list
        # the user asked about.
        for a in access:
            if not a.ok:
                unreachable.append(
                    BatchResult(
                        a.image,
                        error=f"skipped: {a.detail or a.reason}",
                        access_status=a.status,
                    )
                )
        if not pullable:
            log("nothing left to download; every image was unreachable")
            results.extend(unreachable)
            _write_skip_list(unreachable, out_dir, log)
            return results
        items = pullable

    if verify_pulls:
        # Say what verification means before it starts, so the per-image
        # 'ok' that follows is a claim the reader can evaluate.
        if deep_verify:
            log(
                "verifying each image (deep): folder exists, pull marked complete, "
                "layers recorded, then file/dir/symlink/byte counts re-walked and "
                "compared against the census taken at extraction"
            )
        else:
            log(
                "verifying each image (quick): folder exists, .image.json parses, "
                "pull marked complete, layers recorded, folder not empty "
                "(use --deep to re-count every file)"
            )

    def run_one(image: str) -> BatchResult:
        if rate_limited.is_set():
            return BatchResult(image, error="skipped: registry rate limit reached")
        t0 = time.time()
        try:
            dest = puller.pull(
                image,
                out_dir,
                jobs=jobs,
                os_name=os_name,
                arch=arch,
                keep_tar=keep_tar,
                quiet=quiet or concurrency > 1,
                verify=verify,
                strict_tag=strict_tag,
            )
            res = BatchResult(image, dest=dest, seconds=time.time() - t0)
            if verify_pulls:
                # Confirm the folder exists and is complete before calling
                # this image done. Quick by default: the pull just counted
                # the tree, so re-walking every file is only worth it when
                # the user explicitly asks.
                try:
                    check = verify_mod.verify_dest(dest, image=image, quick=not deep_verify)
                    res.verified = check.ok
                    res.verify_status = check.status
                    res.verify_problems = list(check.problems)
                    res.verify_summary = check.summary()
                    res.verify_checks = [c.as_dict() for c in check.checks]
                except OSError as exc:
                    res.verified = False
                    res.verify_status = "missing"
                    res.verify_problems = [str(exc)]
        except KeyboardInterrupt:
            raise
        except RateLimited as exc:
            # Every remaining image will hit the same wall, and each attempt
            # digs the hole deeper, so stop trying.
            rate_limited.set()
            res = BatchResult(image, error=str(exc), seconds=time.time() - t0)
        except BaseException as exc:  # noqa: BLE001 - a batch must survive anything
            res = BatchResult(image, error=f"{type(exc).__name__}: {exc}", seconds=time.time() - t0)
        with lock:
            counter[0] += 1
            mark = "ok  " if res.ok else "FAIL"
            if res.ok:
                # Name the evidence, not just the verdict.
                detail = f"  {res.verify_summary}" if res.verify_summary else ""
            else:
                detail = "  " + (res.error or "; ".join(res.verify_problems) or "unverified")
            log(f"[{counter[0]:>{width}}/{len(items)}] {mark} {image} ({res.seconds:.1f}s){detail}")
        if on_result is not None:
            on_result(res)
        return res

    started = time.time()
    if concurrency <= 1:
        for image in items:
            res = run_one(image)
            results.append(res)
            if rate_limited.is_set():
                log("stopping: registry rate limit reached")
                break
            if stop_on_error and not res.ok:
                log("stopping: --stop-on-error and a pull failed")
                break
    else:
        with ThreadPoolExecutor(max_workers=min(concurrency, len(items))) as pool:
            futures = [pool.submit(run_one, image) for image in items]
            try:
                for fut in futures:
                    results.append(fut.result())
            except BaseException:
                for f in futures:
                    f.cancel()
                raise

    failed = [r for r in results if not r.ok]
    verified = sum(1 for r in results if r.verified)
    log(
        f"\n{len(results) - len(failed)}/{len(items)} ok, {len(failed)} failed "
        f"in {time.time() - started:.1f}s"
    )
    if verify_pulls:
        # The line that answers "did they all actually download?" without
        # anyone having to scroll back through the run.
        kind = "deep-verified" if deep_verify else "verified"
        log(f"{verified}/{len(items)} {kind} on disk")
        checked = next((r.verify_summary for r in results if r.verify_summary), None)
        if checked:
            log(f"  each image: {checked}")
        unattempted = len(items) - len(results)
        if unattempted:
            log(f"  {unattempted} never attempted")
    for r in failed:
        log(f"  FAIL {r.image}: {r.error or '; '.join(r.verify_problems)}")
    if rate_limited.is_set():
        remaining = len(items) - len(results)
        log("")
        log("Stopped: Docker Hub rate limit reached.")
        if remaining > 0:
            log(f"  {remaining} of {len(items)} images were not attempted.")
        if registry_credentials("dockerhub"):
            log("  Already authenticated; wait for the window to reset.")
        else:
            log("  Log in to raise the limit, then rerun:")
            log("    export DOCKERHUB_USERNAME=<your-username>")
            log("    export DOCKERHUB_TOKEN=<personal-access-token>")
            log("  Create a token at https://app.docker.com/settings/personal-access-tokens")

    if unreachable:
        # The list the user asked about included these, so the answer has to
        # account for them rather than quietly returning a shorter list.
        total = len(results) + len(unreachable)
        log("")
        log(
            f"{len(unreachable)} of {total} images were never downloadable "
            f"and were skipped before downloading"
        )
        _write_skip_list(unreachable, out_dir, log)
        results.extend(unreachable)
    return results


def _write_skip_list(skipped: list[BatchResult], out_dir: str, log) -> str | None:
    """Write the unreachable images to a file next to the downloads.

    A count is not actionable on its own; the names are. Written as a
    plain list with the reason as a trailing comment, so the file is both
    readable and directly re-feedable to `dt -f` once the repos come back.
    """
    if not skipped:
        return None
    path = os.path.join(out_dir, SKIPPED_FILE_NAME)
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Images that could not be downloaded, and why.\n")
            fh.write("# Re-runnable with: dt -f this-file\n")
            for r in sorted(skipped, key=lambda x: x.image):
                reason = (r.error or "").removeprefix("skipped: ")
                fh.write(f"{r.image}  # {reason}\n")
    except OSError as exc:
        log(f"  could not write {SKIPPED_FILE_NAME}: {exc}")
        return None
    log(f"  written to {path}")
    return path
