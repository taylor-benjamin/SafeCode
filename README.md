# SAFECODE

[![CI](https://github.com/taylor-benjamin/SafeCode/actions/workflows/ci.yml/badge.svg)](https://github.com/taylor-benjamin/SafeCode/actions/workflows/ci.yml)
[![SAFECODE](https://github.com/taylor-benjamin/SafeCode/actions/workflows/safecode.yml/badge.svg)](https://github.com/taylor-benjamin/SafeCode/actions/workflows/safecode.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A security report card for your repository, written for humans.**

SAFECODE is a GitHub Action that scans a repository for security problems and posts a plain-English report with an **A–F grade** on every pull request. Every finding comes with where it is, why it matters (written for a junior developer), a concrete fix, and the matching **OWASP Top 10 (2025)**, **CWE**, and **NIST SSDF** identifiers.

SAFECODE doesn't reinvent scanning. It runs three established open-source scanners and adds what they don't provide:

| | What it finds |
|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Passwords, API keys, and tokens, including ones deleted from the code but still in git history |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependencies with published vulnerabilities, with the version that fixes them |
| [Semgrep](https://semgrep.dev) | Insecure code: SQL injection, `eval`, cleartext `http://`, disabled TLS verification |
| SAFECODE itself | Repo hygiene checks no scanner does (lockfiles, `.gitignore`, `SECURITY.md`, branch protection), standards mapping, beginner-friendly explanations, and one score |

## What the report looks like

This is SAFECODE's report on [`examples/vulnerable-app`](examples/vulnerable-app), an intentionally insecure demo ([full report](examples/sample-report.md)):

> ### 🔴 Grade F · 0/100
>
> **22 findings**: 🔴 3 critical · 🟠 11 high · 🟡 7 medium · 🔵 1 low · ⚪ 0 info
>
> | | Rule | Result | Standards |
> |---|---|---|---|
> | ❌ | **SC-001** No secrets in code or git history | 1 finding | A07:2025 · CWE-798 · SSDF PS.1 |
> | ❌ | **SC-002** No known-vulnerable dependencies | 8 findings | A03:2025 · CWE-1395 · SSDF PW.4 |
> | ❌ | **SC-003** No SQL injection or unsafe eval | 6 findings | A05:2025 · CWE-89 · CWE-95 · SSDF PW.5 |
> | | *…5 more rules* | | |
>
> **SQL query built from strings**
> `app.py:20` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/) · [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final)
>
> > This SQL query is built by inserting values directly into the query text. Pass values separately, e.g. cursor.execute("... WHERE id = ?", (user_id,)).
>
> - **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
> - **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder.

On a pull request this appears as a single comment that SAFECODE updates on every push. The full report also goes to the workflow run's job summary.

## Quick start

Add `.github/workflows/safecode.yml` to your repository:

```yaml
name: SAFECODE

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write # lets SAFECODE comment on pull requests

jobs:
  scan:
    runs-on: ubuntu-latest # Docker actions need a Linux runner
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0 # full history, so secrets in old commits are found too
      - uses: taylor-benjamin/SafeCode@v0.1.0
        with:
          fail-threshold: "off" # start with reporting only; tighten to e.g. C later
```

That's it: open a pull request and the report appears as a comment.

> **Tip:** for supply-chain safety, pin the action to a full commit SHA instead of a tag (`uses: taylor-benjamin/SafeCode@<sha> # v0.1.0`).

### Inputs

| Input | Default | Description |
|---|---|---|
| `fail-threshold` | `off` | Fail the job if the grade is worse than this letter (`A`, `B`, `C`, `D`). `off` only reports. |
| `comment-on-pr` | `true` | Post and keep updating one report comment on pull requests. |
| `exclude-paths` | | Ignore findings under these paths, comma- or newline-separated. `examples/` excludes a directory; other entries are globs such as `*.min.js`. |
| `checklist` | built-in | Path to your own checklist YAML (see [Customizing](#customizing-the-checklist)). |
| `semgrep-config` | | Extra Semgrep configs: registry packs (`p/python`) or a folder of your own rules (`.safecode/semgrep`). |
| `scan-path` | `.` | Directory to scan, relative to the repository root. |
| `github-token` | `github.token` | Token for the PR comment and the branch-protection check. The default job token is enough. |

### Outputs

| Output | Example | Description |
|---|---|---|
| `grade` | `B` | Letter grade, A to F |
| `score` | `84` | Score from 0 to 100 |
| `findings-count` | `5` | Total number of findings |

Use them in later steps, e.g. `if: steps.safecode.outputs.grade == 'F'`.

## The checklist

| ID | Practice | Checked by | Standards |
|---|---|---|---|
| SC-001 | No secrets in code or git history | Gitleaks | CWE-798 · OWASP A07:2025 · SSDF PS.1 |
| SC-002 | No known-vulnerable dependencies | OSV-Scanner | OWASP A03:2025 · CWE-1395 · SSDF PW.4 |
| SC-003 | No SQL injection or unsafe `eval` | Semgrep | OWASP A05:2025 · CWE-89, CWE-95 · SSDF PW.5 |
| SC-004 | Lockfile present, dependency versions pinned | SAFECODE | SSDF PW.4 · OWASP A03:2025 · CWE-1357 |
| SC-005 | `.gitignore` excludes `.env`, keys, credentials; none are committed | SAFECODE | CWE-538 · OWASP A02:2025 · SSDF PS.1 |
| SC-006 | `SECURITY.md` exists | SAFECODE | SSDF RV.1 |
| SC-007 | Branch protection on the default branch | SAFECODE (GitHub API) | SSDF PS.1, PO.5 · OWASP A08:2025 |
| SC-008 | No cleartext `http://` or disabled TLS verification | Semgrep | OWASP A04:2025 · CWE-319, CWE-295 · SSDF PW.5 |

Notes on individual checks:

- **SC-001** scans the full git history when the checkout has it (`fetch-depth: 0`). The report says so when it only saw a shallow clone.
- **SC-002** reports one finding per vulnerable package, not one per advisory, with the single upgrade that fixes all of them.
- **SC-003 / SC-008** use SAFECODE's own Semgrep rules in [`rules/semgrep/`](rules/semgrep) for Python and JavaScript/TypeScript. Add registry packs with `semgrep-config` for other languages.
- **SC-004** understands npm/yarn/pnpm/bun, pip (`requirements*.txt` pins), Poetry/uv/PDM/Pipenv, Bundler, Composer, Cargo, and Go modules, including workspace lockfiles in parent directories.
- **SC-007** uses read-only API endpoints that the default job token can access, and recognises both classic branch protection and rulesets. Without a repository context it is skipped, never failed.

## How the score works

Every scan starts at **100** and loses points per finding:

| Severity | Points |
|---|---|
| Critical | −25 |
| High | −10 |
| Medium | −4 |
| Low | −1 |
| Info | 0 |

Then:

1. **Each checklist rule deducts at most 40 points.** Thirty unpinned packages are one problem, not thirty, and can't sink the grade on their own.
2. **Extra Semgrep findings** (from `semgrep-config`) that don't belong to a checklist rule count at **half weight**, capped at 20 points in total.
3. **Skipped checks cost nothing**, for example branch protection when no token is available. The report states how many checks actually ran, so a high score on few checks isn't mistaken for a clean bill of health.
4. **Grade:** **A** ≥ 90, **B** ≥ 80, **C** ≥ 70, **D** ≥ 60, **F** below 60.
5. **Any critical finding caps the grade at C.** A leaked secret can never earn an A or B, whatever else is right.

Example: one SQL injection (−10) plus a missing `SECURITY.md` (−1) scores **89 → B**. The report includes a "How this score was calculated" table with exactly these numbers. The formula lives in [`src/safecode/scoring.py`](src/safecode/scoring.py).

## Customizing the checklist

Every rule is data in [`rules/checklist.yml`](rules/checklist.yml): name, description, severity, standards mapping, the "why it matters" text, and the fix. To change them:

1. Copy `rules/checklist.yml` into your repo, e.g. as `.safecode/checklist.yml`.
2. Edit wording or severities, or turn a rule off with `enabled: false`.
3. Point the action at it with `checklist: .safecode/checklist.yml`.

To add your own code rule, write a Semgrep rule with `metadata.safecode-rule` set to a checklist ID (copy one from [`rules/semgrep/`](rules/semgrep)), and pass its folder via `semgrep-config`. The checklist loader validates everything strictly, so a typo like `CWE798` fails with a clear message instead of producing a broken report.

### Ignoring findings

- **Whole directories** (vendored code, fixtures): `exclude-paths: vendor/, tests/fixtures/`
- **A Gitleaks false positive:** add its fingerprint to `.gitleaksignore` ([example](.gitleaksignore))
- **A Semgrep false positive:** add a `# nosemgrep` comment on the line

## How it works

```
             ┌─────────────┐
 repository ─┤  Gitleaks   ├─┐
             │ OSV-Scanner │ │  each tool's JSON      ┌──────────┐   ┌─────────┐   ┌─────────────┐
             │  Semgrep    │ ├─────────────────────▶ │ Finding  │──▶│ mapping │──▶│   scoring   │
             └─────────────┘ │  → one unified schema  │  schema  │   │ OWASP / │   │  A–F grade  │
             ┌─────────────┐ │                        └──────────┘   │ CWE /   │   └──────┬──────┘
             │  hygiene    ├─┘                                       │ SSDF    │          ▼
             │  checks     │                                         └─────────┘   Markdown report
             └─────────────┘                                                       → PR comment
                                                                                   → job summary
```

| Module | Responsibility |
|---|---|
| [`scanners/`](src/safecode/scanners) | Run each tool and convert its output to the unified [`Finding`](src/safecode/schema.py) schema. A missing or crashing tool becomes a note in the report, never a failed run. |
| [`checklist.py`](src/safecode/checklist.py) | The hygiene checks (SC-004 to SC-007) |
| [`mapping.py`](src/safecode/mapping.py) | Attach standard IDs, official names, and links |
| [`scoring.py`](src/safecode/scoring.py) | The scoring formula |
| [`report.py`](src/safecode/report.py) | Markdown rendering, with escaping of all repository-controlled text |
| [`pr_comment.py`](src/safecode/pr_comment.py) | Create or update the single PR comment |

## Security and privacy

- **Secret values never appear** in reports, logs, comments, or outputs. Gitleaks runs with `--redact`, and SAFECODE doesn't read the secret field anyway.
- **Repository content can't inject** links, HTML, or GitHub workflow commands into the report or the job log.
- **Network access:** the [osv.dev](https://osv.dev) API (dependency lookups) and the GitHub API (comment, branch protection). Nothing else, and no telemetry.
- **Pinned supply chain:** base image by digest, scanner binaries by version and SHA-256 checksum, and Python dependencies by version, with SAFECODE's own also pinned by hash.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Limitations

- Docker-based, so it needs a **Linux runner**. The image is built on each run, which adds about 1–2 minutes.
- SAFECODE's own Semgrep rules cover **Python and JavaScript/TypeScript**. Java/Gradle and .NET lockfiles are not checked by SC-004.
- With a `scan-path` subdirectory, Gitleaks still scans the whole repository's history.
- Fork pull requests get a read-only token, so the comment can't be posted. The report is still in the job summary.

## Development

```bash
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e . --no-deps
bash scripts/install-dev-tools.sh # pinned, checksum-verified scanners into .tools/
pytest                            # unit + integration tests
ruff check .
python -m safecode --path examples/vulnerable-app
```

Integration tests run the real scanners and are skipped automatically if one isn't installed. CI runs the test suite on Python 3.11–3.14, builds and runs the Docker action against the demo app, and runs SAFECODE on itself.

## License

[MIT](LICENSE)
