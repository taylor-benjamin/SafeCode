"""Semgrep adapter: insecure code patterns (checklist SC-003 and SC-008).

SAFECODE's own rules live in rules/semgrep/ and declare which checklist rule
they belong to via `metadata.safecode-rule`. Users can add any extra Semgrep
config (e.g. registry packs). Those findings are linked to a checklist rule
by their CWE when possible, and otherwise reported under EXTRA_RULE_ID.

Semgrep 1.x no longer includes matched source lines in its output without a
login, and SAFECODE doesn't want them anyway: a flagged line could contain a
secret. Findings therefore carry file and line only.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from safecode.scanners.base import ScanOutput, relative_path, run_tool, tool_version
from safecode.schema import Finding, Location, Severity, StandardRef, ToolStatus

TOOL = "semgrep"
DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "semgrep"

# Findings from user-supplied configs that don't match any checklist rule.
EXTRA_RULE_ID = "EXTRA"

_ENV = {
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "PYTHONUTF8": "1",  # Semgrep's CLI can crash on non-UTF-8 consoles (Windows dev machines)
}


def scan(target: Path, cwe_to_rule: dict[str, str], extra_configs: tuple[str, ...] = (),
         rules_dir: Path = DEFAULT_RULES_DIR) -> ScanOutput:
    """Run SAFECODE's Semgrep rules (plus any extra configs) over target.

    cwe_to_rule maps CWE IDs to checklist rule IDs, used to place findings
    from extra configs that don't carry `safecode-rule` metadata.
    """
    args = ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet", "--config", str(rules_dir)]
    for config in extra_configs:
        args += ["--config", config]
    args.append(str(target))

    # Semgrep exits 0 on success (findings or not); 1 only with --error. Higher codes are failures.
    output = run_tool(TOOL, args, cwd=target, ok_codes=(0, 1), env=_ENV)
    run = replace(output.run, version=tool_version(TOOL, ["--version"], target))
    if run.status is not ToolStatus.OK:
        return ScanOutput(run)

    try:
        data = json.loads(output.stdout)
    except ValueError:
        return ScanOutput(replace(run, status=ToolStatus.ERROR, detail="could not parse Semgrep output"))

    errors = data.get("errors") or []
    if errors:
        run = replace(run, detail=f"{len(errors)} file(s) or rule(s) could not be processed")
    return ScanOutput(run, parse_report(data, target, cwe_to_rule))


def parse_report(data: dict[str, Any], root: Path, cwe_to_rule: dict[str, str]) -> list[Finding]:
    """Convert Semgrep JSON results into Findings."""
    findings = []
    for result in data.get("results") or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        check_id = str(result.get("check_id", "unknown"))
        cwes = _ids(metadata.get("cwe"), r"CWE-\d+")
        owasp = _ids(metadata.get("owasp"), r"A\d\d:\d{4}")

        rule_id = metadata.get("safecode-rule") or next(
            (cwe_to_rule[c] for c in cwes if c in cwe_to_rule), EXTRA_RULE_ID
        )

        try:
            severity = Severity.parse(str(extra.get("severity", "")))
        except ValueError:
            severity = Severity.MEDIUM

        references = metadata.get("references") or []
        if isinstance(references, str):
            references = [references]

        findings.append(
            Finding(
                rule_id=str(rule_id),
                title=metadata.get("safecode-title") or _humanise(check_id),
                severity=severity,
                source=TOOL,
                message=" ".join(str(extra.get("message", "")).split()),
                location=Location(
                    relative_path(str(result.get("path", "")), root),
                    line=(result.get("start") or {}).get("line"),
                    end_line=(result.get("end") or {}).get("line"),
                ),
                source_rule_id=check_id,
                standards=tuple(StandardRef("CWE", c) for c in cwes)
                + tuple(StandardRef("OWASP", o) for o in owasp),
                references=tuple(str(r) for r in references[:3]),
            )
        )
    return findings


def _ids(value: Any, pattern: str) -> list[str]:
    """Pull standard IDs out of Semgrep metadata, which may be a string or list of
    strings like "CWE-89: Improper Neutralization of ..."."""
    items = value if isinstance(value, list) else [value] if value else []
    found: list[str] = []
    for item in items:
        for match in re.findall(pattern, str(item)):
            if match not in found:
                found.append(match)
    return found


def _humanise(check_id: str) -> str:
    """'safecode.python.sql-built-from-strings' -> 'Sql built from strings'."""
    return check_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").capitalize()
