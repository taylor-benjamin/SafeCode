"""Tests for main.run(): how scanner outcomes become checklist results.

The real adapters are swapped for fakes, so these run without any scanners
installed and can simulate crashes and missing tools.
"""

from dataclasses import replace
from pathlib import Path

import pytest

from safecode import main
from safecode.rules import DEFAULT_CHECKLIST, load_rules
from safecode.scanners.base import ScanOutput
from safecode.schema import CheckStatus, Finding, Location, Severity, ToolRun, ToolStatus


@pytest.fixture
def rules():
    return load_rules(DEFAULT_CHECKLIST)


@pytest.fixture
def config(tmp_path: Path):
    return main.Config(path=tmp_path)


def fake_finding(rule_id, line=1):
    return Finding(rule_id=rule_id, title="t", severity=Severity.HIGH, source="fake",
                   message="m", location=Location("a.py", line))


def ok(tool, findings=(), **kw):
    return lambda config, enabled, rules: ScanOutput(ToolRun(tool, ToolStatus.OK, **kw), list(findings))


def crash(config, enabled, rules):
    raise RuntimeError("adapter bug")


def statuses(result):
    return {check.rule_id: check.status for check in result.checks}


def test_results_become_checklist_statuses(monkeypatch, config, rules):
    monkeypatch.setattr(main, "SCANNERS", {
        "gitleaks": ("gitleaks", ok("gitleaks", [fake_finding("SC-001")])),
        "osv": ("osv-scanner", ok("osv-scanner", detail="no dependency manifests found")),
        "semgrep": ("semgrep", ok("semgrep", [fake_finding("SC-003"), fake_finding("SC-003", 2)])),
    })
    result = main.run(config, rules)
    assert statuses(result)["SC-001"] is CheckStatus.FAILED
    assert statuses(result)["SC-002"] is CheckStatus.PASSED
    assert statuses(result)["SC-003"] is CheckStatus.FAILED
    assert statuses(result)["SC-008"] is CheckStatus.PASSED
    assert next(c for c in result.checks if c.rule_id == "SC-003").summary == "2 findings"
    assert next(c for c in result.checks if c.rule_id == "SC-002").summary == "no dependency manifests found"
    # findings are enriched with standards on the way in
    assert result.findings[0].standards


def test_crashing_adapter_is_reported_and_others_still_run(monkeypatch, config, rules):
    monkeypatch.setattr(main, "SCANNERS", {
        "gitleaks": ("gitleaks", crash),
        "semgrep": ("semgrep", ok("semgrep", [fake_finding("SC-008")])),
    })
    result = main.run(config, rules)
    assert statuses(result)["SC-001"] is CheckStatus.ERROR
    assert "internal error: RuntimeError" in next(t for t in result.tools if t.name == "gitleaks").detail
    assert statuses(result)["SC-008"] is CheckStatus.FAILED


def test_missing_tool_marks_rule_skipped(monkeypatch, config, rules):
    def missing(config, enabled, rules):
        return ScanOutput(ToolRun("gitleaks", ToolStatus.NOT_INSTALLED, detail="x"))

    monkeypatch.setattr(main, "SCANNERS", {"gitleaks": ("gitleaks", missing)})
    assert statuses(main.run(config, rules))["SC-001"] is CheckStatus.SKIPPED


def test_disabled_rule_is_skipped_and_its_findings_dropped(monkeypatch, config, rules):
    rules = {**rules, "SC-003": replace(rules["SC-003"], enabled=False)}
    monkeypatch.setattr(main, "SCANNERS", {
        "semgrep": ("semgrep", ok("semgrep", [fake_finding("SC-003"), fake_finding("SC-008")])),
    })
    result = main.run(config, rules)
    assert statuses(result)["SC-003"] is CheckStatus.SKIPPED
    assert [f.rule_id for f in result.findings if f.source == "fake"] == ["SC-008"]


def test_checks_are_in_checklist_order(monkeypatch, config, rules):
    monkeypatch.setattr(main, "SCANNERS", {"semgrep": ("semgrep", ok("semgrep"))})
    ids = [c.rule_id for c in main.run(config, rules).checks]
    assert ids == [rule_id for rule_id in rules if rule_id in ids]
    assert {"SC-003", "SC-004", "SC-007", "SC-008"} <= set(ids)  # scanner and hygiene checks interleaved


def test_hygiene_checks_run_and_crashes_are_contained(monkeypatch, config, rules):
    monkeypatch.setattr(main, "SCANNERS", {})
    def broken(rule, ctx):
        raise ValueError("bug")
    monkeypatch.setitem(main.checklist.HYGIENE_CHECKS, "file_exists", broken)
    result = main.run(config, rules)
    assert statuses(result)["SC-006"] is CheckStatus.ERROR
    assert statuses(result)["SC-005"] is CheckStatus.FAILED  # empty tmp dir has no .gitignore
    assert statuses(result)["SC-007"] is CheckStatus.SKIPPED  # no GitHub repository known


@pytest.mark.parametrize(("path", "excluded"), [
    ("examples/app.py", True), ("examples", True), ("examplesX/app.py", False),
    ("src/vendor.min.js", True), ("src/app.js", False),
])
def test_is_excluded(path, excluded):
    assert main.is_excluded(path, ("./examples/**", "*.min.js")) is excluded


def test_excluded_findings_are_dropped_and_checks_restated(monkeypatch, tmp_path, rules):
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "requirements.txt").write_text("requests\n", encoding="utf-8")
    config = main.Config(path=tmp_path, exclude_paths=("examples/",))
    monkeypatch.setattr(main, "SCANNERS", {
        "gitleaks": ("gitleaks", ok("gitleaks", [Finding(rule_id="SC-001", title="t", severity=Severity.CRITICAL,
                                                         source="fake", message="m",
                                                         location=Location("examples/app.py", 3))])),
    })
    result = main.run(config, rules)
    assert statuses(result)["SC-001"] is CheckStatus.PASSED
    assert next(c for c in result.checks if c.rule_id == "SC-004").summary == "no issues outside excluded paths"
    assert result.excluded_count == 2
    assert "2 finding(s) in excluded paths (examples/) were ignored." in result.notes
