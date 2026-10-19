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


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Run `npm install` and commit.", "Run `npm install` and commit."),
        ("Use `pip-compile` / `uv pip compile`.", "Use `pip-compile` / `uv pip compile`."),
        ("[x](https://evil.example) then `ok`", r"\[x\](https://evil.example) then `ok`"),
        ("unbalanced ` tick **here**", r"unbalanced tick \*\*here\*\*"),
    ],
)
def test_prose_keeps_inline_code_but_escapes_the_rest(raw, expected):
    assert report._prose(raw) == expected


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


def test_grade_header_and_breakdown(rules):
    from safecode import scoring

    result = ScanResult(target=".", checks=[CheckResult("SC-003", CheckStatus.FAILED, "6 findings")])
    result.add_findings([make(rules, line=n) for n in range(1, 7)])
    score = scoring.compute(result, rules)
    md = report.render(result, rules, score)
    assert md.index("### 🟠 Grade D · 60/100") < md.index("**6 findings**")
    assert "| **SC-003** No SQL injection or unsafe eval | 6 | −40 (capped from −60) |" in md
    assert "| **Total** | | −40 → **60/100** |" in md
    assert "Based on 1 of 8 checks; 7 could not run" in md


def test_hidden_findings_link_to_run(rules):
    result = ScanResult(target=".")
    result.add_findings([make(rules, line=n) for n in range(1, 4)])
    md = report.render(result, rules, max_findings=1, details_url="https://github.com/o/r/actions/runs/1")
    assert "See [the job summary](https://github.com/o/r/actions/runs/1) for the full list." in md
