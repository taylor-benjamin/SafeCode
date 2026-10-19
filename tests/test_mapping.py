"""Tests for mapping findings to OWASP / CWE / NIST SSDF."""

from dataclasses import replace

import pytest

from safecode import mapping
from safecode.rules import DEFAULT_CHECKLIST, load_rules
from safecode.schema import Finding, Location, Severity, StandardRef


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_CHECKLIST)


def finding(rule_id="SC-008", standards=(), fix=""):
    return Finding(rule_id=rule_id, title="t", severity=Severity.MEDIUM, source="semgrep",
                   message="m", location=Location("a.py", 1), standards=standards, fix=fix)


class TestDescribe:
    def test_owasp_2025_has_name_and_official_url(self):
        ref = mapping.describe(mapping.OWASP, "A05:2025")
        assert ref.name == "Injection"
        assert ref.url == "https://owasp.org/Top10/2025/A05_2025-Injection/"

    def test_unknown_owasp_id_falls_back_to_index(self):
        ref = mapping.describe(mapping.OWASP, "A03:2021")
        assert ref.name == ""
        assert ref.url == "https://owasp.org/Top10/"

    def test_cwe_link_works_even_without_a_known_name(self):
        ref = mapping.describe(mapping.CWE, "CWE-99999")
        assert ref.url == "https://cwe.mitre.org/data/definitions/99999.html"

    def test_ssdf(self):
        ref = mapping.describe(mapping.NIST_SSDF, "RV.1")
        assert ref.name.startswith("Identify and Confirm Vulnerabilities")


class TestShippedChecklistIsFullyDescribed:
    def test_every_mapped_id_has_a_name(self, rules):
        """Catches typos in checklist.yml (e.g. a non-existent SSDF practice)."""
        for rule in rules.values():
            for ref in mapping.standards_for_rule(rule):
                assert ref.name, f"{rule.id}: no catalog entry for {ref.framework} {ref.id}"


class TestEnrich:
    def test_adds_rule_standards_why_and_fix(self, rules):
        enriched = mapping.enrich(finding(), rules)
        ids = [ref.id for ref in enriched.standards]
        assert ids[0] == "A04:2025"  # OWASP listed first
        assert {"CWE-319", "CWE-295", "PW.5"} <= set(ids)
        assert enriched.why_it_matters == rules["SC-008"].why_it_matters
        assert enriched.fix == rules["SC-008"].fix

    def test_specific_cwe_narrows_the_rules_alternatives(self, rules):
        enriched = mapping.enrich(finding(standards=(StandardRef("CWE", "CWE-295"),)), rules)
        cwes = [ref.id for ref in enriched.standards if ref.framework == mapping.CWE]
        assert cwes == ["CWE-295"]

    def test_extra_cwe_is_added_alongside_rule_cwe(self, rules):
        enriched = mapping.enrich(finding("SC-002", standards=(StandardRef("CWE", "CWE-1321"),)), rules)
        cwes = {ref.id for ref in enriched.standards if ref.framework == mapping.CWE}
        assert cwes == {"CWE-1395", "CWE-1321"}
        assert next(r for r in enriched.standards if r.id == "CWE-1321").name == "Prototype Pollution"

    def test_finding_specific_fix_wins(self, rules):
        enriched = mapping.enrich(finding("SC-002", fix="Upgrade lodash to 4.17.21 or later."), rules)
        assert enriched.fix == "Upgrade lodash to 4.17.21 or later."

    def test_unknown_rule_still_gets_names(self, rules):
        enriched = mapping.enrich(finding("EXTRA", standards=(StandardRef("CWE", "CWE-89"),)), rules)
        assert enriched.standards[0].name == "SQL Injection"
        assert enriched.fix == ""

    def test_no_duplicate_standards(self, rules):
        enriched = mapping.enrich(finding("SC-003", standards=(StandardRef("CWE", "CWE-89"),) * 2), rules)
        ids = [ref.id for ref in enriched.standards]
        assert len(ids) == len(set(ids))


def test_cwe_to_rule_only_uses_enabled_semgrep_rules(rules):
    assert mapping.cwe_to_rule(rules) == {"CWE-89": "SC-003", "CWE-95": "SC-003",
                                          "CWE-319": "SC-008", "CWE-295": "SC-008"}
    disabled = {**rules, "SC-003": replace(rules["SC-003"], enabled=False)}
    assert "CWE-89" not in mapping.cwe_to_rule(disabled)
