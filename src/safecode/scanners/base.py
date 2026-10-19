"""Shared plumbing for running external scanner binaries.

Every adapter (Semgrep, Gitleaks, OSV-Scanner) goes through run_tool(), which
guarantees one behaviour: a missing binary, a timeout, or a crash becomes a
ToolRun with a non-OK status that the report can show. It never raises, so a
broken scanner can't take the whole scan down with it.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from safecode.schema import ToolRun, ToolStatus

DEFAULT_TIMEOUT_S = 600
# Keep stderr excerpts short: they go into the report, and long dumps bury the
# useful line. Adapters must not pass flags that make a tool print secrets.
_MAX_DETAIL_CHARS = 300


@dataclass(frozen=True)
class ToolOutput:
    """What came back from running a tool. stdout is empty unless run.status is OK."""

    run: ToolRun
    stdout: str = ""


def run_tool(
    name: str,
    args: list[str],
    *,
    cwd: Path,
    ok_codes: tuple[int, ...] = (0,),
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> ToolOutput:
    """Run `name` with `args` and capture its output.

    ok_codes lists exit codes that mean "the tool worked". Several scanners
    exit 1 when they *find* something, which is a success from our side.
    """
    executable = shutil.which(name)
    if executable is None:
        return ToolOutput(ToolRun(name, ToolStatus.NOT_INSTALLED, detail=f"{name} not found on PATH"))

    started = time.monotonic()
    try:
        completed = subprocess.run(
            [executable, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolOutput(
            ToolRun(name, ToolStatus.TIMEOUT, detail=f"timed out after {timeout_s}s", duration_s=timeout_s)
        )
    except OSError as exc:
        return ToolOutput(ToolRun(name, ToolStatus.ERROR, detail=f"could not start: {exc.strerror or exc}"))

    duration = round(time.monotonic() - started, 2)
    if completed.returncode not in ok_codes:
        detail = f"exit code {completed.returncode}: {_last_line(completed.stderr)}"
        return ToolOutput(ToolRun(name, ToolStatus.ERROR, detail=detail, duration_s=duration))

    return ToolOutput(ToolRun(name, ToolStatus.OK, duration_s=duration), stdout=completed.stdout)


def tool_version(name: str, args: list[str], cwd: Path) -> str:
    """Return the first line a tool prints for its version flag, or "" if unavailable."""
    output = run_tool(name, args, cwd=cwd, timeout_s=30)
    lines = output.stdout.strip().splitlines()
    return lines[0].strip() if lines else ""


def _last_line(text: str) -> str:
    """The last non-empty line of stderr, which is usually the actual error."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        return "no error output"
    return lines[-1][:_MAX_DETAIL_CHARS]
