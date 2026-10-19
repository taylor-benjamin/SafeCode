# SAFECODE

> Work in progress (v0.1 under construction). Full documentation, the install snippet, and the scoring formula arrive in a later phase.

SAFECODE is a GitHub Action that scans a repository with [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks), and [OSV-Scanner](https://github.com/google/osv-scanner), checks it against a short list of secure-development practices, and posts a plain-English report with an A–F grade. Every finding is mapped to OWASP Top 10 (2025), CWE, and NIST SSDF identifiers.

## Development

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e . --no-deps
scripts/install-dev-tools.sh  # optional: pinned scanners into .tools/ for integration tests
pytest
python -m safecode --path examples/vulnerable-app
```

Integration tests run the real scanners and are skipped automatically if a scanner isn't installed. See [examples/sample-report.md](examples/sample-report.md) for what a report looks like.
