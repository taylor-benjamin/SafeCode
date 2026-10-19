"""Tests for the scoring formula. Each test pins down one sentence of the documented formula."""

import pytest

from safecode import scoring
from safecode.rules import DEFAULT_CHECKLIST, load_rules
from safecode.schema import CheckResult, CheckStatus, Finding, Location, ScanResult, Severity


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_CHECKLIST)


def result_with(*specs, checks=()):
    """specs: (rule_id, severity, count) tuples."""
    result = ScanResult(target=".", checks=list(checks))
    line = 0
    for rule_id, severity, count in specs:
        for _ in range(count):
            line += 1
            result.add_findings([Finding(rule_id=rule_id, title="t", severity=severity, source="x",
                                         message="m", location=Location("f.py", line))])
    return result


def test_clean_repo_scores_100_A(rules):
    score = scoring.compute(result_with(), rules)
    assert (score.score, score.grade, score.deductions) == (100, "A", ())


@pytest.mark.parametrize(("severity", "expected"), [
    (Severity.CRITICAL, 75), (Severity.HIGH, 90), (Severity.MEDIUM, 96), (Severity.LOW, 99), (Severity.INFO, 100),
])
def test_severity_weights(rules, severity, expected):
    assert scoring.compute(result_with(("SC-003", severity, 1)), rules).score == expected


def test_each_rule_capped_at_40(rules):
    score = scoring.compute(result_with(("SC-003", Severity.HIGH, 6)), rules)
    assert score.score == 60
    [deduction] = score.deductions
    assert (deduction.raw_points, deduction.points, deduction.capped) == (60, 40, True)


def test_caps_are_per_rule_so_several_rules_add_up(rules):
    score = scoring.compute(result_with(("SC-003", Severity.HIGH, 6), ("SC-008", Severity.HIGH, 6)), rules)
    assert score.score == 20


def test_score_never_negative(rules):
    specs = [(rule_id, Severity.CRITICAL, 2) for rule_id in rules]
    assert scoring.compute(result_with(*specs), rules).score == 0


def test_extra_findings_half_weight_and_capped_at_20(rules):
    assert scoring.compute(result_with(("EXTRA", Severity.HIGH, 1)), rules).score == 95
    assert scoring.compute(result_with(("EXTRA", Severity.HIGH, 10)), rules).score == 80


def test_critical_finding_caps_grade_at_C(rules):
    # A half-weight critical costs 12.5 points (score 88, normally a B) but must not earn a B.
    score = scoring.compute(result_with(("EXTRA", Severity.CRITICAL, 1)), rules)
    assert score.score == 88
    assert score.grade == "C"
    assert score.critical_cap_applied


def test_critical_cap_does_not_raise_a_worse_grade(rules):
    score = scoring.compute(result_with(("SC-001", Severity.CRITICAL, 1), ("SC-003", Severity.HIGH, 4)), rules)
    assert (score.score, score.grade, score.critical_cap_applied) == (35, "F", False)


@pytest.mark.parametrize(("value", "grade"), [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"),
                                              (70, "C"), (69, "D"), (60, "D"), (59, "F"), (0, "F")])
def test_grade_boundaries(value, grade):
    assert scoring.grade_for(value) == grade


def test_only_evaluated_checks_count_as_run(rules):
    checks = [CheckResult("SC-001", CheckStatus.PASSED), CheckResult("SC-002", CheckStatus.FAILED),
              CheckResult("SC-007", CheckStatus.SKIPPED), CheckResult("SC-003", CheckStatus.ERROR)]
    score = scoring.compute(result_with(checks=checks), rules)
    assert (score.checks_run, score.checks_total) == (2, 8)


def test_deductions_sorted_biggest_first(rules):
    score = scoring.compute(result_with(("SC-006", Severity.LOW, 1), ("SC-001", Severity.CRITICAL, 1)), rules)
    assert [d.rule_id for d in score.deductions] == ["SC-001", "SC-006"]


@pytest.mark.parametrize(("grade", "threshold", "worse"), [("D", "C", True), ("C", "C", False),
                                                           ("A", "D", False), ("F", "D", True)])
def test_is_worse(grade, threshold, worse):
    assert scoring.is_worse(grade, threshold) is worse
