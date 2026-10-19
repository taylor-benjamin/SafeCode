"""Turn findings into a 0-100 score and an A-F grade.

The formula (also documented in the README):

1. Start at 100.
2. Each finding deducts points by severity: critical 25, high 10, medium 4,
   low 1, info 0.
3. Each checklist rule deducts at most 40 points in total, so one noisy rule
   (say, 30 unpinned packages) can't sink the grade on its own.
4. Findings from extra Semgrep configs that don't map to a checklist rule
   count at half weight, capped at 20 points together.
5. Checks that were skipped or errored deduct nothing; the report states how
   many checks actually ran so a high score on few checks isn't misleading.
6. Grade: A >= 90, B >= 80, C >= 70, D >= 60, otherwise F.
7. Any critical finding caps the grade at C. With the default weights a
   critical already costs 25 points, so this mainly matters for half-weight
   extra findings or customised weights; it guarantees that a leaked secret
   can never earn an A or B.
"""

from __future__ import annotations

from dataclasses import dataclass

from safecode.rules import Rule
from safecode.schema import CheckStatus, ScanResult, Severity

SEVERITY_POINTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
RULE_CAP = 40
EXTRA_WEIGHT = 0.5
EXTRA_CAP = 20
GRADE_THRESHOLDS = (("A", 90), ("B", 80), ("C", 70), ("D", 60))
GRADES = ("A", "B", "C", "D", "F")
CRITICAL_GRADE_CAP = "C"

# Pseudo rule ID for the combined extra-findings bucket in the breakdown.
EXTRA_BUCKET = "EXTRA"


@dataclass(frozen=True)
class Deduction:
    """Points lost to one checklist rule (or to the extra-findings bucket)."""

    rule_id: str
    findings: int
    raw_points: float  # before the cap
    points: float  # what actually counted

    @property
    def capped(self) -> bool:
        return self.points < self.raw_points


@dataclass(frozen=True)
class Score:
    score: int
    grade: str
    deductions: tuple[Deduction, ...]
    checks_run: int  # passed or failed, i.e. actually evaluated
    checks_total: int  # enabled checklist rules
    critical_cap_applied: bool


def compute(result: ScanResult, rules: dict[str, Rule]) -> Score:
    """Score a scan result according to the formula in the module docstring."""
    per_rule: dict[str, list[float]] = {}
    for finding in result.findings:
        points = float(SEVERITY_POINTS[finding.severity])
        bucket = finding.rule_id if finding.rule_id in rules else EXTRA_BUCKET
        if bucket == EXTRA_BUCKET:
            points *= EXTRA_WEIGHT
        per_rule.setdefault(bucket, []).append(points)

    deductions = []
    for rule_id, points in per_rule.items():
        raw = sum(points)
        cap = EXTRA_CAP if rule_id == EXTRA_BUCKET else RULE_CAP
        deductions.append(Deduction(rule_id, len(points), raw, min(raw, cap)))
    # Biggest losses first: that is what a reader should fix first.
    deductions.sort(key=lambda d: (-d.points, d.rule_id))

    score = max(0, round(100 - sum(d.points for d in deductions)))
    grade = grade_for(score)
    has_critical = any(f.severity is Severity.CRITICAL for f in result.findings)
    capped = has_critical and GRADES.index(grade) < GRADES.index(CRITICAL_GRADE_CAP)
    if capped:
        grade = CRITICAL_GRADE_CAP

    evaluated = {CheckStatus.PASSED, CheckStatus.FAILED}
    return Score(
        score=score,
        grade=grade,
        deductions=tuple(deductions),
        checks_run=sum(1 for c in result.checks if c.status in evaluated),
        checks_total=sum(1 for r in rules.values() if r.enabled),
        critical_cap_applied=capped,
    )


def grade_for(score: int) -> str:
    for grade, minimum in GRADE_THRESHOLDS:
        if score >= minimum:
            return grade
    return "F"


def is_worse(grade: str, threshold: str) -> bool:
    """True if grade is strictly worse than threshold ("D" is worse than "C")."""
    return GRADES.index(grade) > GRADES.index(threshold)
