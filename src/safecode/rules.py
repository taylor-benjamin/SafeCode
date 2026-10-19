"""Load and validate the checklist in rules/checklist.yml.

The checklist is user-editable, so this loader is strict: a typo in a rule
should produce a clear error message naming the rule and field, not a
confusing crash somewhere deep in the scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from safecode.schema import Severity

# The repo ships its checklist at <repo>/rules/checklist.yml. In the Docker
# image the same layout is copied to /app, so this relative lookup works in both.
DEFAULT_CHECKLIST = Path(__file__).resolve().parents[2] / "rules" / "checklist.yml"

CHECK_TYPES = frozenset(
    {"gitleaks", "osv", "semgrep", "lockfile", "gitignore", "file_exists", "branch_protection"}
)

# Accepted ID formats per standard. Validating these catches mistakes like
# "CWE798" or "A3:2025" that would otherwise produce broken links in reports.
MAPPING_PATTERNS = {
    "owasp": re.compile(r"^A(0[1-9]|10):20\d\d$"),
    "cwe": re.compile(r"^CWE-\d+$"),
    "nist_ssdf": re.compile(r"^(PO|PS|PW|RV)\.\d+$"),
}

RULE_ID_PATTERN = re.compile(r"^SC-\d{3}$")
REQUIRED_TEXT_FIELDS = ("name", "description", "why_it_matters", "fix")


class ChecklistError(ValueError):
    """Raised when checklist.yml is malformed."""


@dataclass(frozen=True)
class Rule:
    """One checklist rule, as written in checklist.yml."""

    id: str
    name: str
    description: str
    severity: Severity
    check_type: str
    why_it_matters: str
    fix: str
    check_options: dict[str, Any] = field(default_factory=dict)
    mapping: dict[str, tuple[str, ...]] = field(default_factory=dict)
    enabled: bool = True


def load_rules(path: Path = DEFAULT_CHECKLIST) -> dict[str, Rule]:
    """Read checklist.yml and return its rules keyed by ID, in file order.

    Disabled rules are included (with enabled=False) so the report can say
    they were turned off rather than pretending they don't exist.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ChecklistError(f"cannot read checklist {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ChecklistError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ChecklistError(f"{path} must contain a top-level 'rules:' list")
    if document.get("version") != 1:
        raise ChecklistError(f"{path}: unsupported checklist version {document.get('version')!r}")

    rules: dict[str, Rule] = {}
    for index, raw in enumerate(document["rules"]):
        rule = _parse_rule(raw, where=f"{path.name} rule #{index + 1}")
        if rule.id in rules:
            raise ChecklistError(f"duplicate rule id {rule.id}")
        rules[rule.id] = rule
    return rules


def _parse_rule(raw: Any, where: str) -> Rule:
    """Validate one raw YAML mapping and convert it into a Rule."""
    if not isinstance(raw, dict):
        raise ChecklistError(f"{where}: each rule must be a mapping")

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not RULE_ID_PATTERN.match(rule_id):
        raise ChecklistError(f"{where}: 'id' must look like SC-001, got {rule_id!r}")
    where = f"rule {rule_id}"

    for name in REQUIRED_TEXT_FIELDS:
        value = raw.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ChecklistError(f"{where}: '{name}' is required and must be text")

    try:
        severity = Severity.parse(str(raw.get("severity", "")))
    except ValueError:
        allowed = ", ".join(s.value for s in Severity)
        raise ChecklistError(f"{where}: 'severity' must be one of {allowed}") from None

    check = raw.get("check")
    if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
        allowed = ", ".join(sorted(CHECK_TYPES))
        raise ChecklistError(f"{where}: 'check.type' must be one of {allowed}")
    check_options = {k: v for k, v in check.items() if k != "type"}

    return Rule(
        id=rule_id,
        name=raw["name"].strip(),
        description=raw["description"].strip(),
        severity=severity,
        check_type=check["type"],
        check_options=check_options,
        mapping=_parse_mapping(raw.get("mapping", {}), where),
        why_it_matters=raw["why_it_matters"].strip(),
        fix=raw["fix"].strip(),
        enabled=bool(raw.get("enabled", True)),
    )


def _parse_mapping(raw: Any, where: str) -> dict[str, tuple[str, ...]]:
    """Validate the mapping block: known frameworks, well-formed IDs."""
    if not isinstance(raw, dict):
        raise ChecklistError(f"{where}: 'mapping' must be a mapping of framework -> list of IDs")

    mapping: dict[str, tuple[str, ...]] = {}
    for framework, ids in raw.items():
        pattern = MAPPING_PATTERNS.get(framework)
        if pattern is None:
            allowed = ", ".join(MAPPING_PATTERNS)
            raise ChecklistError(f"{where}: unknown mapping framework {framework!r} (use {allowed})")
        if isinstance(ids, str):
            ids = [ids]
        if not isinstance(ids, list):
            raise ChecklistError(f"{where}: mapping.{framework} must be a list")
        for standard_id in ids:
            if not isinstance(standard_id, str) or not pattern.match(standard_id):
                raise ChecklistError(f"{where}: invalid {framework} id {standard_id!r}")
        mapping[framework] = tuple(ids)
    return mapping
