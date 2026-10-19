"""Gitleaks adapter: secrets in files and in git history (checklist SC-001).

Secret handling, in order of defence:
1. Gitleaks runs with --redact, so its report never contains the secret.
2. parse_report() never reads the `Secret` or `Match` fields anyway, nor the
   commit author's email address.
3. Findings carry only rule name, file, line, and commit.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from safecode.scanners.base import ScanOutput, relative_path, run_tool, tool_version
from safecode.schema import Finding, Location, Severity, ToolStatus

TOOL = "gitleaks"


def scan(target: Path, rule_id: str, severity: Severity) -> ScanOutput:
    """Scan target for secrets, including full git history when available."""
    notes: list[str] = []
    repo_root, shallow = _git_info(target)

    if repo_root is None:
        mode, root = "dir", target
        notes.append("Not a git repository, so only current files were checked for secrets (no history).")
    else:
        # Note: in git mode Gitleaks reads the whole repository's history, even
        # when scan-path points at a subdirectory. Paths are relative to the repo root.
        mode, root = "git", repo_root
        if shallow:
            notes.append(
                "This is a shallow clone, so older git history was not checked for secrets. "
                "Use `fetch-depth: 0` in actions/checkout to scan the full history."
            )

    with tempfile.TemporaryDirectory(prefix="safecode-gitleaks-") as tmp:
        report_path = Path(tmp) / "report.json"
        args = [
            mode,
            "--redact",
            "--no-banner",
            "--log-level", "error",
            "--exit-code", "0",  # "leaks found" is not an error for us
            "--report-format", "json",
            "--report-path", str(report_path),
            str(root),
        ]
        output = run_tool(TOOL, args, cwd=target)
        run = replace(output.run, version=tool_version(TOOL, ["version"], target))
        if run.status is not ToolStatus.OK:
            return ScanOutput(run, notes=notes)

        try:
            raw = report_path.read_text(encoding="utf-8").strip()
            data = json.loads(raw) if raw else []
        except (OSError, ValueError):
            return ScanOutput(replace(run, status=ToolStatus.ERROR, detail="could not read Gitleaks report"), notes=notes)

    return ScanOutput(run, parse_report(data, root, rule_id, severity), notes)


def parse_report(data: list[dict[str, Any]], root: Path, rule_id: str, severity: Severity) -> list[Finding]:
    """Convert Gitleaks JSON report entries into Findings. Never touches secret values."""
    findings = []
    for leak in data:
        gitleaks_rule = str(leak.get("RuleID", "unknown"))
        commit = str(leak.get("Commit") or "") or None
        line = leak.get("StartLine") or None
        location = Location(relative_path(str(leak.get("File", "")), root), line=line, commit=commit)

        kind = gitleaks_rule.replace("-", " ")
        if commit:
            message = (
                f"A value that looks like a {kind} was committed in {commit[:7]}. "
                "Even if it has since been removed from the file, it is still in git history."
            )
        else:
            message = f"A value that looks like a {kind} is written directly in this file."

        findings.append(
            Finding(
                rule_id=rule_id,
                title=f"Possible secret ({gitleaks_rule})",
                severity=severity,
                source=TOOL,
                message=message,
                location=location,
                source_rule_id=gitleaks_rule,
            )
        )
    return findings


def _git_info(target: Path) -> tuple[Path | None, bool]:
    """Return (repo root, is_shallow) for target, or (None, False) if it isn't in a git repo."""
    output = run_tool("git", ["rev-parse", "--show-toplevel", "--is-shallow-repository"], cwd=target, timeout_s=30)
    lines = output.stdout.strip().splitlines()
    if output.run.status is not ToolStatus.OK or len(lines) < 2:
        return None, False
    return Path(lines[0]), lines[1].strip() == "true"
