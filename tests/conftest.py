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
