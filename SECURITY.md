# Security Policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

Use GitHub's [private vulnerability reporting][gh-private] on this
repository (Security -> Report a vulnerability). If that is unavailable,
open an issue saying only that you have a security report and asking for a
contact address, with no details.

[gh-private]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Please include:

- what an attacker can do, and what they need to start
- a reference to an image or repository that reproduces it, if one exists
- the version (`st --version`) and platform

Expect an acknowledgement within a week. This is a small project without a
paid security team, so that is a best effort, not an SLA.

## What counts as a vulnerability here

This tool downloads and unpacks archives built by strangers: image layers and
repository tarballs. The security boundary is: **extracting a hostile image
or repository must not affect anything outside the destination directory.**
Reports that cross that line are in scope.

In scope:

- Writing outside the destination directory: `../` members, absolute paths,
  symlinks that escape the root, or a link target that resolves outside it.
- Anything that lets a crafted image run code during a pull or extraction.
- A layer whose contents do not match the digest the manifest promised,
  being accepted while `--verify` is on.
- Leaking registry credentials, for example forwarding the registry
  `Authorization` header to the CDN a blob redirect points at.
- Leaking `GITHUB_TOKEN`, for example forwarding it to the codeload host the
  API redirects a tarball download to, or writing it into the history clone's
  git config or a report.
- Resource exhaustion that a small manifest can trigger, such as a
  decompression bomb that fills the disk with no bound.

Out of scope:

- Malicious content sitting inertly inside the extracted rootfs or tree.
  Extracting a bad image or repository is the point of the tool; the result
  is data, and it is on the operator not to execute it.
- Secrets baked into a public image or committed to a public repository.
  Report those to the owner.
- Docker Hub rate limits, and anything requiring an already-compromised
  machine or a modified local install.

## Using this safely

- Treat every extracted rootfs and repository tree as untrusted data. Grep
  it, do not run it.
- Do not `chroot` into output, and do not extract as root. The tool never
  needs it and creates no device or FIFO nodes.
- Extracted trees frequently contain credentials that the image author
  committed by accident. Keep them out of version control and off shared
  storage. This repository's `.gitignore` covers the default output paths
  for that reason.
- Keep `--verify` on, which is the default. It checks each layer against
  the sha256 the manifest declares.

## Supported versions

Fixes land on `main` and in the next release. There are no long-term
support branches.
