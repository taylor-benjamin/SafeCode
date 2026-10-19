"""Unit tests for the scanner adapters' parsers, using hand-built scanner output.

These don't need the scanner binaries installed: they check that each tool's
JSON is translated into the unified schema correctly, and that secret values
never survive the translation.
"""

import json
import tempfile
from pathlib import Path

from safecode.scanners import gitleaks, osv, semgrep
from safecode.scanners.semgrep import EXTRA_RULE_ID
from safecode.schema import ScanResult, Severity

# A real absolute path on every OS ("/repo" is not absolute on Windows).
ROOT = Path(tempfile.gettempdir()).resolve() / "repo"


class TestGitleaksParser:
    # Deliberately *un*redacted, as if --redact had failed: the parser must still not leak.
    LEAK = {
        "RuleID": "generic-api-key",
        "Description": "Detected a Generic API Key",
        "StartLine": 7,
        "File": str(ROOT / "config" / "settings.py"),
        "Commit": "",
        "Secret": "s3cr3t-value-that-must-never-appear",
        "Match": "API_KEY = 's3cr3t-value-that-must-never-appear'",
        "Email": "dev@example.com",
        "Author": "Dev",
    }

    def test_maps_fields_into_schema(self):
        [finding] = gitleaks.parse_report([self.LEAK], ROOT, "SC-001", Severity.CRITICAL)
        assert finding.rule_id == "SC-001"
        assert finding.severity is Severity.CRITICAL
        assert finding.source_rule_id == "generic-api-key"
        assert str(finding.location) == "config/settings.py:7"
        assert "written directly in this file" in finding.message

    def test_secret_value_and_author_email_never_appear(self):
        findings = gitleaks.parse_report([self.LEAK], ROOT, "SC-001", Severity.CRITICAL)
        result = ScanResult(target=".", findings=findings)
        serialised = json.dumps(result.to_dict())
        assert "s3cr3t-value" not in serialised
        assert "dev@example.com" not in serialised

    def test_history_finding_mentions_commit(self):
        leak = {**self.LEAK, "File": "config/settings.py", "Commit": "0123456789abcdef"}
        [finding] = gitleaks.parse_report([leak], ROOT, "SC-001", Severity.CRITICAL)
        assert finding.location.commit == "0123456789abcdef"
        assert "0123456" in finding.message
        assert "history" in finding.message


def _osv_package(name, version, groups, vulns, ecosystem="npm"):
    return {"package": {"name": name, "version": version, "ecosystem": ecosystem},
            "groups": groups, "vulnerabilities": vulns}


def _osv_vuln(vuln_id, summary, fixed, name="lodash", ecosystem="npm", cwes=(), label=None):
    vuln = {
        "id": vuln_id,
        "summary": summary,
        "affected": [{"package": {"name": name, "ecosystem": ecosystem},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
        "database_specific": {"cwe_ids": list(cwes)},
    }
    if label:
        vuln["database_specific"]["severity"] = label
    return vuln


class TestOsvParser:
    def make_report(self, tmp_path):
        (tmp_path / "package-lock.json").write_text('{\n  "lodash": "4.17.15"\n}\n', encoding="utf-8")
        lodash = _osv_package(
            "lodash", "4.17.15",
            groups=[
                {"ids": ["GHSA-aaaa"], "aliases": ["CVE-2020-0001", "GHSA-aaaa"], "max_severity": "7.4"},
                {"ids": ["GHSA-bbbb"], "aliases": ["CVE-2021-0002", "GHSA-bbbb"], "max_severity": "9.1"},
            ],
            vulns=[
                _osv_vuln("GHSA-aaaa", "Prototype pollution", "4.17.19", cwes=["CWE-1321"]),
                _osv_vuln("GHSA-bbbb", "Command injection", "4.17.21", cwes=["CWE-77"]),
            ],
        )
        source = {"path": str(tmp_path / "package-lock.json"), "type": "lockfile"}
        # The same package reported twice for the same file, as OSV-Scanner v2 does.
        return {"results": [{"source": source, "packages": [lodash]}, {"source": source, "packages": [lodash]}]}

    def test_one_finding_per_package_with_worst_severity(self, tmp_path):
        [finding] = osv.parse_report(self.make_report(tmp_path), tmp_path, "SC-002", Severity.HIGH)
        assert finding.title == "lodash 4.17.15 has 2 known vulnerabilities"
        assert finding.severity is Severity.CRITICAL  # CVSS 9.1
        assert finding.message.index("CVE-2021-0002") < finding.message.index("CVE-2020-0001")  # worst first

    def test_fix_version_resolves_every_advisory(self, tmp_path):
        [finding] = osv.parse_report(self.make_report(tmp_path), tmp_path, "SC-002", Severity.HIGH)
        assert finding.fix == "Upgrade lodash to 4.17.21 or later."

    def test_location_and_standards(self, tmp_path):
        [finding] = osv.parse_report(self.make_report(tmp_path), tmp_path, "SC-002", Severity.HIGH)
        assert str(finding.location) == "package-lock.json:2"
        assert {ref.id for ref in finding.standards} == {"CWE-1321", "CWE-77"}
        assert finding.references[0] == "https://osv.dev/vulnerability/GHSA-bbbb"

    def test_severity_falls_back_to_label_then_default(self):
        labelled = _osv_vuln("GHSA-x", "s", "2.0", label="MODERATE")
        assert osv._severity("", [labelled], Severity.HIGH) is Severity.MEDIUM
        assert osv._severity(None, [], Severity.HIGH) is Severity.HIGH

    def test_version_ordering_is_numeric(self):
        assert osv._version_key("2.10.0") > osv._version_key("2.9.9")


def _semgrep_result(check_id, metadata, severity="ERROR", path=str(ROOT / "app.py"), line=3):
    return {"check_id": check_id, "path": path, "start": {"line": line}, "end": {"line": line},
            "extra": {"message": "Bad\n  thing.", "severity": severity, "metadata": metadata,
                      "lines": "requires login"}}


class TestSemgrepParser:
    def test_safecode_rules_link_via_metadata(self):
        data = {"results": [_semgrep_result(
            "safecode.python.sql-built-from-strings",
            {"safecode-rule": "SC-003", "safecode-title": "SQL query built from strings", "cwe": ["CWE-89"]},
        )]}
        [finding] = semgrep.parse_report(data, ROOT, {})
        assert finding.rule_id == "SC-003"
        assert finding.title == "SQL query built from strings"
        assert finding.severity is Severity.HIGH
        assert finding.message == "Bad thing."
        assert str(finding.location) == "app.py:3"

    def test_third_party_rule_links_via_cwe(self):
        data = {"results": [_semgrep_result(
            "python.lang.security.audit.formatted-sql-query",
            {"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
             "owasp": ["A03:2021 - Injection"]},
            severity="WARNING",
        )]}
        [finding] = semgrep.parse_report(data, ROOT, {"CWE-89": "SC-003"})
        assert finding.rule_id == "SC-003"
        assert finding.severity is Severity.MEDIUM
        assert finding.title == "Formatted sql query"
        assert {ref.id for ref in finding.standards} == {"CWE-89", "A03:2021"}

    def test_unmatched_third_party_rule_is_extra(self):
        data = {"results": [_semgrep_result("some.rule", {"cwe": "CWE-1004"}, severity="INFO")]}
        [finding] = semgrep.parse_report(data, ROOT, {"CWE-89": "SC-003"})
        assert finding.rule_id == EXTRA_RULE_ID
        assert finding.severity is Severity.INFO

    def test_matched_source_lines_are_not_kept(self):
        data = {"results": [_semgrep_result("x", {"safecode-rule": "SC-003"})]}
        [finding] = semgrep.parse_report(data, ROOT, {})
        assert "requires login" not in json.dumps(ScanResult(".", findings=[finding]).to_dict())
