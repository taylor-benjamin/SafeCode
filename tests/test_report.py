"""Tests for Markdown report rendering."""

import re

import pytest

from safecode import mapping, report
from safecode.rules import DEFAULT_CHECKLIST, load_rules
from safecode.schema import CheckResult, CheckStatus, Finding, Location, ScanResult, Severity, ToolRun, ToolStatus


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_CHECKLIST)


def make(rules, severity=Severity.HIGH, path="app.py", line=1, **kw):
    base = dict(rule_id="SC-003", title="SQL query built from strings", severity=severity, source="semgrep",
                message="Query built with an f-string.", location=Location(path, line))
    base.update(kw)
    return mapping.enrich(Finding(**base), rules)


def test_summary_counts_and_checklist(rules):
    result = ScanResult(target=".")
    result.add_findings([make(rules), make(rules, Severity.CRITICAL, line=2)])
    result.checks = [CheckResult("SC-003", CheckStatus.FAILED, "2 findings")]
    md = report.render(result, rules)
    assert "**2 findings**: 🔴 1 critical · 🟠 1 high · 🟡 0 medium" in md
    assert "| ❌ | **SC-003** No SQL injection or unsafe eval | 2 findings |" in md


def test_finding_block_has_location_standards_why_and_fix(rules):
    result = ScanResult(target=".")
    result.add_findings([make(rules)])
    md = report.render(result, rules)
    assert "`app.py:1` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/" in md
    assert "**Why it matters:**" in md and "**Fix:**" in md


def test_critical_and_high_expanded_others_collapsed(rules):
    result = ScanResult(target=".")
    result.add_findings([make(rules, Severity.HIGH), make(rules, Severity.LOW, line=9)])
    md = report.render(result, rules)
    assert "#### 🟠 High (1)" in md
    assert "<summary><b>🔵 Low (1)</b></summary>" in md


def test_untrusted_text_cannot_inject_markdown(rules):
    result = ScanResult(target=".")
    result.add_findings([make(
        rules,
        path="evil`](https://evil.example)`.py",
        title="[click me](https://evil.example) <img src=x>",
        message="**bold** | table-breaker",
    )])
    md = report.render(result, rules)
    assert "[click me](https://evil.example)" not in md
    assert r"\[click me\]" in md
    assert not re.search(r"(?<!\\)<img", md)  # only the escaped (inert) form \<img may appear
    assert r"\*\*bold\*\* \| table-breaker" in md
    assert "`evil'](https://evil.example)'.py:1`" in md  # backticks neutralised inside the code span


def test_only_safe_reference_urls_are_shown(rules):
    result = ScanResult(target=".")
    result.add_findings([make(rules, references=("https://osv.dev/vulnerability/X", "javascript:alert(1)"))])
    md = report.render(result, rules)
    assert "<https://osv.dev/vulnerability/X>" in md
    assert "javascript:" not in md


def test_truncates_long_reports(rules):
    result = ScanResult(target=".")
    result.add_findings([make(rules, line=n) for n in range(1, 11)])
    md = report.render(result, rules, max_findings=3)
    assert md.count("**SQL query built from strings**") == 3
    assert "and 7 more finding(s)" in md


def test_clean_scan_and_tool_failures(rules):
    result = ScanResult(target=".", tools=[ToolRun("gitleaks", ToolStatus.NOT_INSTALLED, detail="not on PATH")],
                        notes=["Shallow clone."])
    md = report.render(result, rules, repo_name="octo/repo")
    assert "for `octo/repo`" in md
    assert "No findings." in md
    assert "⏭️ not installed" in md
    assert "ℹ️ Shallow clone." in md
