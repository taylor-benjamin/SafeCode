"""Tests for the unified finding schema and redaction helpers."""

import json

import pytest

from safecode.redaction import REDACTED, redact, scrub
from safecode.schema import Finding, Location, ScanResult, Severity


def make_finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="SC-003",
        title="SQL injection",
        severity=Severity.HIGH,
        source="semgrep",
        message="Query built with string formatting",
        location=Location("app/db.py", line=12),
        source_rule_id="safecode.python.sqli",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestSeverity:
    def test_rank_orders_worst_first(self):
        ranks = [s.rank for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)]
        assert ranks == sorted(ranks)
        assert Severity.CRITICAL.rank < Severity.INFO.rank

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("HIGH", Severity.HIGH),
            (" critical ", Severity.CRITICAL),
            ("ERROR", Severity.HIGH),  # Semgrep
            ("WARNING", Severity.MEDIUM),  # Semgrep
            ("moderate", Severity.MEDIUM),  # GitHub advisories
        ],
    )
    def test_parse_normalises_scanner_labels(self, raw, expected):
        assert Severity.parse(raw) is expected

    def test_parse_rejects_unknown(self):
        with pytest.raises(ValueError):
            Severity.parse("catastrophic")


class TestLocation:
    def test_str_with_line(self):
        assert str(Location("a.py", line=3)) == "a.py:3"

    def test_str_with_history_commit(self):
        assert str(Location("a.py", line=3, commit="abcdef1234567")) == "a.py:3 (commit abcdef1)"


class TestFinding:
    def test_fingerprint_is_stable(self):
        assert make_finding().fingerprint == make_finding().fingerprint

    def test_fingerprint_ignores_wording_but_not_location(self):
        reworded = make_finding(message="different text")
        moved = make_finding(location=Location("app/db.py", line=99))
        assert reworded.fingerprint == make_finding().fingerprint
        assert moved.fingerprint != make_finding().fingerprint

    def test_fingerprint_without_location(self):
        repo_wide = make_finding(location=None)
        assert len(repo_wide.fingerprint) == 16


class TestScanResult:
    def test_add_findings_deduplicates(self):
        result = ScanResult(target=".")
        result.add_findings([make_finding(), make_finding()])
        result.add_findings([make_finding()])
        assert len(result.findings) == 1

    def test_counts_include_zero_severities(self):
        result = ScanResult(target=".")
        result.add_findings([make_finding(), make_finding(severity=Severity.LOW, location=Location("b.py"))])
        counts = result.counts_by_severity()
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.LOW] == 1
        assert counts[Severity.CRITICAL] == 0
        assert list(counts) == list(Severity)

    def test_sorted_findings_worst_first_then_path(self):
        result = ScanResult(target=".")
        low = make_finding(severity=Severity.LOW, location=Location("a.py", 1))
        crit_b = make_finding(severity=Severity.CRITICAL, location=Location("b.py", 1))
        crit_a = make_finding(severity=Severity.CRITICAL, location=Location("a.py", 5))
        result.add_findings([low, crit_b, crit_a])
        assert result.sorted_findings() == [crit_a, crit_b, low]

    def test_to_dict_is_json_serialisable(self):
        result = ScanResult(target=".")
        result.add_findings([make_finding()])
        data = json.loads(json.dumps(result.to_dict()))
        assert data["findings"][0]["severity"] == "high"
        assert data["findings"][0]["fingerprint"] == make_finding().fingerprint


class TestRedaction:
    def test_long_secret_keeps_only_prefix(self):
        secret = "AKIAABCDEFGHIJKLMNOP"
        redacted = redact(secret)
        assert redacted.startswith("AKIA")
        assert REDACTED in redacted
        assert secret not in redacted
        assert "EFGH" not in redacted

    def test_short_secret_fully_hidden(self):
        assert redact("hunter2") == REDACTED

    def test_scrub_removes_every_occurrence(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        text = f'token = "{secret}"  # also {secret}'
        cleaned = scrub(text, [secret])
        assert secret not in cleaned
        assert cleaned.count(REDACTED) == 2

    def test_scrub_handles_overlapping_secrets(self):
        inner, outer = "password12345678", "xxpassword12345678yy"
        cleaned = scrub(f"{outer} {inner}", [inner, outer])
        assert inner not in cleaned and outer not in cleaned
