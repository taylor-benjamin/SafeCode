"""Shared pytest setup.

If the pinned scanners were installed locally into .tools/ (see README), put
them on PATH so the integration tests can find them. In CI the scanners are
installed system-wide and this is a no-op.
"""

import os
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_APP = ROOT / "examples" / "vulnerable-app"

_LOCAL_TOOL_DIRS = [
    ROOT / ".tools" / "bin",
    ROOT / ".tools" / "semgrep-venv" / "Scripts",  # Windows venv layout
    ROOT / ".tools" / "semgrep-venv" / "bin",  # POSIX venv layout
]
for directory in _LOCAL_TOOL_DIRS:
    if directory.is_dir():
        os.environ["PATH"] = f"{directory}{os.pathsep}{os.environ['PATH']}"


_ACTIONS_ENV = (
    "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT", "GITHUB_TOKEN",
    "GITHUB_WORKSPACE", "GITHUB_API_URL", "GITHUB_ACTIONS", "GITHUB_SERVER_URL", "GITHUB_RUN_ID",
    "INPUT_FAIL-THRESHOLD", "INPUT_COMMENT-ON-PR", "INPUT_SCAN-PATH",
    "INPUT_SEMGREP-CONFIG", "INPUT_GITHUB-TOKEN",
)


@pytest.fixture(autouse=True)
def isolated_from_actions_env(monkeypatch):
    """Tests run inside GitHub Actions in CI; make sure they never see (or call out with)
    the real workflow's repository, token, or summary file."""
    for name in _ACTIONS_ENV:
        monkeypatch.delenv(name, raising=False)


def requires_tool(name: str):
    """Skip a test when an external scanner binary isn't installed."""
    return pytest.mark.skipif(shutil.which(name) is None, reason=f"{name} not installed")


@pytest.fixture
def example_app(tmp_path: Path) -> Path:
    """A fresh copy of the vulnerable example app outside this git repo.

    Copying keeps tests independent of this repo's git state (Semgrep and
    Gitleaks both behave differently inside a git checkout).
    """
    target = tmp_path / "vulnerable-app"
    shutil.copytree(EXAMPLE_APP, target)
    return target
