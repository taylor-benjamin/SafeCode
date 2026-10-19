"""Tests for loading and validating rules/checklist.yml."""

from pathlib import Path

import pytest
import yaml

from safecode.rules import DEFAULT_CHECKLIST, ChecklistError, load_rules
from safecode.schema import Severity

VALID_RULE = {
    "id": "SC-100",
    "name": "Example",
    "description": "Example rule.",
    "severity": "low",
    "check": {"type": "file_exists", "paths": ["CODEOWNERS"]},
    "mapping": {"nist_ssdf": ["PO.1"]},
    "why_it_matters": "Because.",
    "fix": "Do the thing.",
}


def write_checklist(tmp_path: Path, rules: list[dict], version: int = 1) -> Path:
    path = tmp_path / "checklist.yml"
    path.write_text(yaml.safe_dump({"version": version, "rules": rules}), encoding="utf-8")
    return path


class TestShippedChecklist:
    """The checklist that ships with SAFECODE must always load cleanly."""

    def test_all_v01_rules_present(self):
        rules = load_rules(DEFAULT_CHECKLIST)
        assert list(rules) == [f"SC-00{n}" for n in range(1, 9)]

    def test_every_rule_maps_to_at_least_one_standard(self):
        for rule in load_rules(DEFAULT_CHECKLIST).values():
            assert any(rule.mapping.values()), rule.id

    def test_spec_mappings(self):
        rules = load_rules(DEFAULT_CHECKLIST)
        assert "CWE-798" in rules["SC-001"].mapping["cwe"]
        assert "CWE-538" in rules["SC-005"].mapping["cwe"]
        assert "RV.1" in rules["SC-006"].mapping["nist_ssdf"]
        assert rules["SC-001"].severity is Severity.CRITICAL

    def test_check_options_are_passed_through(self):
        rules = load_rules(DEFAULT_CHECKLIST)
        assert ".env" in rules["SC-005"].check_options["patterns"]
        assert "SECURITY.md" in rules["SC-006"].check_options["paths"]


class TestValidation:
    def test_valid_custom_rule_loads(self, tmp_path):
        rules = load_rules(write_checklist(tmp_path, [VALID_RULE]))
        rule = rules["SC-100"]
        assert rule.enabled
        assert rule.mapping == {"nist_ssdf": ("PO.1",)}

    def test_single_string_mapping_is_accepted(self, tmp_path):
        rule = {**VALID_RULE, "mapping": {"cwe": "CWE-20"}}
        assert load_rules(write_checklist(tmp_path, [rule]))["SC-100"].mapping == {"cwe": ("CWE-20",)}

    def test_disabled_rule_is_kept(self, tmp_path):
        rules = load_rules(write_checklist(tmp_path, [{**VALID_RULE, "enabled": False}]))
        assert rules["SC-100"].enabled is False

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"id": "rule-1"}, "'id' must look like SC-001"),
            ({"severity": "urgent"}, "'severity' must be one of"),
            ({"check": {"type": "magic"}}, "'check.type' must be one of"),
            ({"fix": ""}, "'fix' is required"),
            ({"mapping": {"owasp": ["A3:2025"]}}, "invalid owasp id"),
            ({"mapping": {"cwe": ["CWE798"]}}, "invalid cwe id"),
            ({"mapping": {"iso27001": ["A.5"]}}, "unknown mapping framework"),
        ],
    )
    def test_bad_rule_gives_clear_error(self, tmp_path, change, message):
        path = write_checklist(tmp_path, [{**VALID_RULE, **change}])
        with pytest.raises(ChecklistError, match=message):
            load_rules(path)

    def test_duplicate_ids_rejected(self, tmp_path):
        with pytest.raises(ChecklistError, match="duplicate"):
            load_rules(write_checklist(tmp_path, [VALID_RULE, VALID_RULE]))

    def test_unknown_version_rejected(self, tmp_path):
        with pytest.raises(ChecklistError, match="version"):
            load_rules(write_checklist(tmp_path, [VALID_RULE], version=2))

    def test_invalid_yaml_rejected(self, tmp_path):
        path = tmp_path / "checklist.yml"
        path.write_text("rules: [unclosed", encoding="utf-8")
        with pytest.raises(ChecklistError, match="not valid YAML"):
            load_rules(path)
