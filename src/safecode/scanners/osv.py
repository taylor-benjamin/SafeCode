"""OSV-Scanner adapter: known-vulnerable dependencies (checklist SC-002).

OSV-Scanner reads lockfiles and manifests and looks every package up in the
osv.dev database. SAFECODE reports one finding per vulnerable package (per
manifest) rather than one per advisory: an old lodash can have six advisories
but needs one fix, and a report with 35 near-identical entries buries the
signal. The finding's severity is that of its worst advisory, and the
suggested version fixes all of them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from safecode.scanners.base import ScanOutput, relative_path, run_tool, tool_version
from safecode.schema import Finding, Location, Severity, StandardRef, ToolStatus

TOOL = "osv-scanner"

# OSV-Scanner v2 exit codes: 0 = clean, 1 = vulnerabilities found,
# 128 = no package manifests found. Anything else is a real error.
EXIT_NO_PACKAGES = 128


def scan(target: Path, rule_id: str, default_severity: Severity) -> ScanOutput:
    """Scan every manifest and lockfile under target."""
    args = ["scan", "source", "--recursive", "--format", "json", str(target)]
    output = run_tool(TOOL, args, cwd=target, ok_codes=(0, 1, EXIT_NO_PACKAGES))
    version = tool_version(TOOL, ["--version"], target).removeprefix("osv-scanner version:").strip()
    run = replace(output.run, version=version)
    if run.status is not ToolStatus.OK:
        return ScanOutput(run)
    if output.returncode == EXIT_NO_PACKAGES:
        return ScanOutput(replace(run, detail="no dependency manifests found"))

    try:
        data = json.loads(output.stdout)
    except ValueError:
        return ScanOutput(replace(run, status=ToolStatus.ERROR, detail="could not parse OSV-Scanner output"))
    return ScanOutput(run, parse_report(data, target, rule_id, default_severity))


@dataclass
class _Advisory:
    """One group of aliased advisories (e.g. CVE + GHSA + PYSEC for the same bug)."""

    primary: str
    osv_id: str
    summary: str
    severity: Severity
    vulns: list[dict[str, Any]]


# How many advisories to name in a finding's message before summarising the rest.
_MAX_LISTED = 3


def parse_report(data: dict[str, Any], root: Path, rule_id: str, default_severity: Severity) -> list[Finding]:
    """Convert OSV-Scanner JSON into one Finding per vulnerable package per manifest."""
    # (manifest, ecosystem, lowercase name) -> (display name, version, advisories by primary ID).
    # OSV-Scanner v2 can report the same manifest twice (a direct pass and a
    # resolved-transitive pass), so packages are merged on this key.
    packages: dict[tuple[str, str, str], tuple[str, str, dict[str, _Advisory]]] = {}

    for result in data.get("results") or []:
        manifest = relative_path(str((result.get("source") or {}).get("path", "")), root)
        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name, version = package.get("name", "?"), package.get("version", "?")
            ecosystem = package.get("ecosystem", "")
            key = (manifest, ecosystem, name.lower())
            _, _, advisories = packages.setdefault(key, (name, version, {}))
            vulns_by_id = {v.get("id"): v for v in entry.get("vulnerabilities") or []}

            for group in entry.get("groups") or []:
                ids = list(group.get("ids") or [])
                primary = _primary_id(list(group.get("aliases") or ids))
                if primary in advisories:
                    continue
                vulns = [vulns_by_id[i] for i in ids if i in vulns_by_id]
                advisories[primary] = _Advisory(
                    primary=primary,
                    osv_id=ids[0] if ids else primary,
                    summary=next((v["summary"] for v in vulns if v.get("summary")), ""),
                    severity=_severity(group.get("max_severity"), vulns, default_severity),
                    vulns=vulns,
                )

    findings = []
    for (manifest, ecosystem, _), (name, version, advisories) in packages.items():
        if not advisories:
            continue
        ranked = sorted(advisories.values(), key=lambda a: (a.severity.rank, a.primary))
        all_vulns = [v for a in ranked for v in a.vulns]
        fixed = _fixed_version(all_vulns, name, ecosystem, version)
        count = len(ranked)

        listed = "; ".join(f"{a.primary} ({a.summary.rstrip('.')})" if a.summary else a.primary
                           for a in ranked[:_MAX_LISTED])
        if count > _MAX_LISTED:
            listed += f"; and {count - _MAX_LISTED} more"

        findings.append(
            Finding(
                rule_id=rule_id,
                title=f"{name} {version} has {count} known vulnerabilit{'y' if count == 1 else 'ies'}",
                severity=ranked[0].severity,
                source=TOOL,
                message=f"{name} {version} ({ecosystem}) is affected by {listed}.",
                location=Location(manifest, line=_find_line(root / manifest, name)),
                source_rule_id=f"{ecosystem}/{name.lower()}",
                # CWEs of the advisories named in the message only; a long tail of CWEs is noise.
                standards=tuple(
                    StandardRef("CWE", cwe) for cwe in _cwe_ids([v for a in ranked[:_MAX_LISTED] for v in a.vulns])
                ),
                fix=f"Upgrade {name} to {fixed} or later." if fixed else "",
                references=tuple(f"https://osv.dev/vulnerability/{a.osv_id}" for a in ranked[:_MAX_LISTED]),
            )
        )
    return findings


def _primary_id(ids: list[str]) -> str:
    """Prefer the CVE ID (most widely recognised), then a GitHub advisory, then anything."""
    for prefix in ("CVE-", "GHSA-"):
        for vuln_id in ids:
            if vuln_id.startswith(prefix):
                return vuln_id
    return ids[0] if ids else "unknown advisory"


def _severity(max_severity: Any, vulns: list[dict[str, Any]], default: Severity) -> Severity:
    """Map the group's CVSS base score to a severity, falling back to the advisory's label."""
    try:
        score = float(max_severity)
    except (TypeError, ValueError):
        score = None
    if score is not None and score > 0:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
    for vuln in vulns:
        label = (vuln.get("database_specific") or {}).get("severity")
        if isinstance(label, str):
            try:
                return Severity.parse(label)
            except ValueError:
                continue
    return default


def _cwe_ids(vulns: list[dict[str, Any]]) -> list[str]:
    """CWE IDs attached to the advisories (GitHub advisories include these)."""
    cwes: list[str] = []
    for vuln in vulns:
        for cwe in (vuln.get("database_specific") or {}).get("cwe_ids") or []:
            if isinstance(cwe, str) and re.fullmatch(r"CWE-\d+", cwe) and cwe not in cwes:
                cwes.append(cwe)
    return cwes


def _fixed_version(vulns: list[dict[str, Any]], name: str, ecosystem: str, current: str) -> str:
    """The lowest version that fixes every advisory in the group and is newer than current.

    Advisories list fixed versions per affected range; we take, for each
    advisory, the smallest fix above the current version, then the largest of
    those so the suggestion resolves the whole group. Returns "" if unknown.
    """
    needed: list[tuple[int, ...]] = []
    labels: dict[tuple[int, ...], str] = {}
    current_key = _version_key(current)
    for vuln in vulns:
        candidates = []
        for affected in vuln.get("affected") or []:
            pkg = affected.get("package") or {}
            if pkg.get("name", "").lower() != name.lower() or pkg.get("ecosystem") != ecosystem:
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    fixed = event.get("fixed")
                    if fixed and _version_key(fixed) > current_key:
                        candidates.append(fixed)
        if candidates:
            best = min(candidates, key=_version_key)
            needed.append(_version_key(best))
            labels[_version_key(best)] = best
    return labels[max(needed)] if needed else ""


def _version_key(version: str) -> tuple[int, ...]:
    """A rough sortable key for dotted versions ("2.10.1" -> (2, 10, 1)).

    Good enough for picking a suggested upgrade; it ignores pre-release tags.
    """
    return tuple(int(part) for part in re.findall(r"\d+", version.split("+")[0])[:4]) or (0,)


def _find_line(manifest: Path, package: str) -> int | None:
    """Best-effort line number of the package in its manifest, so the report can point at it."""
    try:
        lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    pattern = re.compile(rf"(^|[\"'/\s]){re.escape(package)}([\"'\s=<>~!@:\[]|$)", re.IGNORECASE)
    for number, text in enumerate(lines, start=1):
        if pattern.search(text):
            return number
    return None
