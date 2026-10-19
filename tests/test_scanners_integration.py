"""End-to-end tests with the real scanners against examples/vulnerable-app.

Each test is skipped automatically if its scanner isn't installed. OSV tests
also need network access to osv.dev.
"""

import json
import random
import string
import subprocess
from pathlib import Path

import pytest
from conftest import requires_tool

from safecode import main
from safecode.mapping import cwe_to_rule
from safecode.rules import DEFAULT_CHECKLIST, load_rules
from safecode.scanners import gitleaks, osv, semgrep
from safecode.schema import Severity, ToolStatus

pytestmark = pytest.mark.integration

FAKE_KEY_IN_EXAMPLE = "q7Zt2LmX9vR4kP8wN3bY6cJ1hF5dS0gA"


def _random_secret() -> str:
    """A high-entropy fake credential, built at test time so it never sits in this repo."""
    rng = random.Random(1234)
    return "".join(rng.choices(string.ascii_letters + string.digits, k=32))


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@requires_tool("gitleaks")
class TestGitleaks:
    def test_finds_hardcoded_key_without_leaking_it(self, example_app):
        output = gitleaks.scan(example_app, "SC-001", Severity.CRITICAL)
        assert output.run.status is ToolStatus.OK
        assert [str(f.location) for f in output.findings] == ["app.py:12"]
        assert "only current files" in output.notes[0]  # not a git repo
        assert FAKE_KEY_IN_EXAMPLE not in json.dumps([f.__dict__ for f in output.findings], default=str)

    @requires_tool("git")
    def test_finds_secret_that_only_exists_in_history(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "test@example.com")
        _git(repo, "config", "user.name", "Test")
        (repo / "config.py").write_text(f'api_key = "{_random_secret()}"\n', encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "add config")
        (repo / "config.py").write_text("import os\napi_key = os.environ['API_KEY']\n", encoding="utf-8")
        _git(repo, "commit", "-q", "-am", "move key to env")

        output = gitleaks.scan(repo, "SC-001", Severity.CRITICAL)
        assert output.run.status is ToolStatus.OK
        [finding] = output.findings
        assert finding.location.path == "config.py"
        assert finding.location.commit  # found in history, not the working tree
        assert _random_secret() not in finding.message


@requires_tool("osv-scanner")
class TestOsv:
    def test_finds_vulnerable_dependencies(self, example_app):
        output = osv.scan(example_app, "SC-002", Severity.HIGH)
        assert output.run.status is ToolStatus.OK, output.run.detail
        names = {f.source_rule_id for f in output.findings}
        assert {"npm/lodash", "npm/minimist", "PyPI/pyyaml", "PyPI/jinja2", "PyPI/requests"} <= names
        lodash = next(f for f in output.findings if f.source_rule_id == "npm/lodash")
        assert lodash.fix.startswith("Upgrade lodash to ")
        assert lodash.location.path == "package-lock.json"

    def test_no_manifests_is_a_pass_not_an_error(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
        output = osv.scan(tmp_path, "SC-002", Severity.HIGH)
        assert output.run.status is ToolStatus.OK
        assert output.findings == []


@requires_tool("semgrep")
class TestSemgrep:
    EXPECTED = {
        ("app.py", 15, "SC-008"), ("app.py", 20, "SC-003"), ("app.py", 25, "SC-003"),
        ("app.py", 31, "SC-003"), ("app.py", 36, "SC-008"),
        ("server.js", 10, "SC-008"), ("server.js", 14, "SC-003"), ("server.js", 19, "SC-003"),
        ("server.js", 24, "SC-003"), ("server.js", 28, "SC-008"),
    }

    def test_flags_every_planted_bug_and_nothing_else(self, example_app):
        output = semgrep.scan(example_app, cwe_to_rule(load_rules(DEFAULT_CHECKLIST)))
        assert output.run.status is ToolStatus.OK, output.run.detail
        found = {(f.location.path, f.location.line, f.rule_id) for f in output.findings}
        assert found == self.EXPECTED

    def test_no_false_positives_on_safe_code(self, tmp_path):
        (tmp_path / "ok.py").write_text(
            '"""Docs at http://docs.vendor.com are fine in a docstring."""\n'
            "import requests\n"
            'URL = "https://api.vendor.com"\n'
            'LOCAL = "http://localhost:8000/health"\n'
            'NS = {"svg": "http://www.w3.org/2000/svg"}\n'
            "def f(conn, uid):\n"
            '    conn.execute("SELECT * FROM t WHERE id = ?", (uid,))\n'
            '    eval("1 + 1")\n'
            "    return requests.get(URL, timeout=5)\n",
            encoding="utf-8",
        )
        (tmp_path / "ok.js").write_text(
            'const base = "https://api.vendor.com";\n'
            'const dev = "http://127.0.0.1:3000";\n'
            'function g(db, id) { return db.query("SELECT * FROM t WHERE id = ?", [id]); }\n'
            "const agent = { rejectUnauthorized: true };\n",
            encoding="utf-8",
        )
        output = semgrep.scan(tmp_path, {})
        assert output.run.status is ToolStatus.OK, output.run.detail
        assert output.findings == []


@requires_tool("gitleaks")
@requires_tool("semgrep")
def test_full_run_writes_report(example_app, tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    report_path = tmp_path / "report.md"
    assert main.main(["--path", str(example_app), "--report-out", str(report_path)]) == 0
    md = report_path.read_text(encoding="utf-8")
    assert "## 🛡️ SAFECODE security report" in md
    assert "**SC-001** No secrets in code or git history | 1 finding" in md
    assert FAKE_KEY_IN_EXAMPLE not in md
