# Security policy

SAFECODE is a security tool that runs inside other people's CI pipelines, with access to their code and a GitHub token. Vulnerabilities in it matter, and reports are very welcome.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |
| older   | ❌ |

Fixes are released as a new patch version. Pin the action to a release tag or commit SHA, and update when a security release is announced.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub instead:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the problem, the impact, and how to reproduce it (a minimal repository or workflow file is ideal).

You can expect an acknowledgement within 7 days and a status update at least every 14 days until the issue is resolved. Once a fix is released, you will be credited in the advisory unless you prefer not to be.

## What counts as a vulnerability

Examples of issues we want to hear about:

- A secret value from the scanned repository appearing in a report, PR comment, job summary, log, or action output.
- The GitHub token being exposed, logged, or sent anywhere other than the GitHub API over HTTPS.
- Content in a scanned repository (file names, code, advisory text) that can inject links, HTML, or workflow commands into the report, the PR comment, or the job log.
- A way for a pull request to make SAFECODE overwrite or edit comments it did not create.
- Tampering with the scanner binaries or dependencies installed in the Docker image.

Not vulnerabilities (please open a normal issue instead):

- Findings in `examples/vulnerable-app/`: that code is intentionally insecure.
- False positives or false negatives from Semgrep, Gitleaks, or OSV-Scanner rules (report upstream for their built-in rules, or here for SAFECODE's own rules in `rules/semgrep/`).
- Disagreements with the scoring weights.

## How SAFECODE protects you

These are the design rules a report would show we have broken:

- **Secrets are never printed.** Gitleaks runs with `--redact`, SAFECODE never reads the secret field of its output, and Semgrep code snippets are not included in reports.
- **The token stays in the Authorization header.** It is hidden from `repr()`, never logged, and only sent to `https://` API URLs.
- **Untrusted text is escaped** before it goes into Markdown, and the job log is printed with workflow commands paused (`::stop-commands::`).
- **Everything in the image is pinned.** The base image is pinned by digest, the scanner binaries by version and SHA-256 checksum, and Python dependencies by version, with SAFECODE's own also pinned by hash.
- **No telemetry.** Semgrep metrics and version checks are disabled. The only network calls are to the osv.dev vulnerability database and the GitHub API.
