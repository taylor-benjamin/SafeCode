"""End-to-end test of main() as it runs inside GitHub Actions, with scanners and
the GitHub API faked: outputs, job summary, PR comment, fail-threshold, and
workflow-command protection in the log."""

import json

import pytest

from safecode import main
from safecode.scanners.base import ScanOutput
from safecode.schema import Finding, Location, Severity, ToolRun, ToolStatus

TOKEN = "ghs_actiontoken0000000000"


class FakeGitHub:
    repo = "octo/app"

    def __init__(self):
        self.posted = []

    def get(self, path):
        return (200, [])

    def request(self, method, path, body=None):
        if method == "GET":
            return self.get(path)
        self.posted.append((method, path, body["body"]))
        return (201, {})


@pytest.fixture
def actions_env(tmp_path, monkeypatch):
    """Simulate the environment GitHub gives a Docker action on a pull_request event."""
    repo = tmp_path / "workspace"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7}, "repository": {"default_branch": "main"}}))
    files = {name: tmp_path / name for name in ("summary.md", "output.txt")}
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_WORKSPACE": str(repo),
        "GITHUB_REPOSITORY": "octo/app",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_STEP_SUMMARY": str(files["summary.md"]),
        "GITHUB_OUTPUT": str(files["output.txt"]),
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "123",
        "INPUT_GITHUB-TOKEN": TOKEN,
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    # One high-severity code finding; no real scanners or network.
    finding = Finding(rule_id="SC-003", title="SQL query built from strings", severity=Severity.HIGH,
                      source="semgrep", message="::add-mask::sneaky", location=Location("app.py", 1))
    monkeypatch.setattr(main, "SCANNERS", {
        "semgrep": ("semgrep", lambda c, e, r: ScanOutput(ToolRun("semgrep", ToolStatus.OK), [finding])),
    })
    gh = FakeGitHub()
    monkeypatch.setattr(main.github, "client_from_env", lambda repo="", token="": gh)
    return files, gh


def outputs(files):
    lines = files["output.txt"].read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


def test_writes_outputs_summary_and_comment(actions_env, capsys):
    files, gh = actions_env
    assert main.main([]) == 0

    # SC-003 high (-10), SC-005 no .gitignore (-4), SC-006 no SECURITY.md (-1).
    # SC-007 is skipped: the fake API's branch response isn't usable, which must not cost points.
    result = outputs(files)
    assert result == {"grade": "B", "score": "85", "findings-count": "3"}

    summary = files["summary.md"].read_text(encoding="utf-8")
    assert f"Grade {result['grade']} · {result['score']}/100" in summary

    [(method, path, body)] = gh.posted
    assert (method, path) == ("POST", "/repos/octo/app/issues/7/comments")
    assert body.startswith("<!-- safecode-report -->")

    log = capsys.readouterr().out
    assert TOKEN not in log
    # Repo-controlled text is printed only while workflow commands are paused.
    stop = log.index("::stop-commands::")
    token = log[stop:].split("\n", 1)[0].removeprefix("::stop-commands::")
    assert stop < log.index("::add-mask::sneaky") < log.index(f"::{token}::")


def test_fail_threshold(actions_env, monkeypatch, capsys):
    monkeypatch.setenv("INPUT_FAIL-THRESHOLD", "A")
    assert main.main([]) == 1
    assert "::error title=SAFECODE::Grade B (85/100) is worse than the fail-threshold A." in capsys.readouterr().out
    monkeypatch.setenv("INPUT_FAIL-THRESHOLD", "B")
    assert main.main([]) == 0


def test_comment_disabled(actions_env, monkeypatch):
    files, gh = actions_env
    monkeypatch.setenv("INPUT_COMMENT-ON-PR", "false")
    main.main([])
    assert gh.posted == []


def test_missing_token_is_noted_not_fatal(actions_env, monkeypatch):
    files, gh = actions_env
    monkeypatch.delenv("INPUT_GITHUB-TOKEN")
    assert main.main([]) == 0
    assert gh.posted == []
    assert "No GitHub token available" in files["summary.md"].read_text(encoding="utf-8")
