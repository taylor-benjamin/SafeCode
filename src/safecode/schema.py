"""The unified finding schema.

SAFECODE wraps three scanners (Semgrep, Gitleaks, OSV-Scanner) and runs its
own repo-hygiene checks. Each of those speaks a different output format. This
module defines the single shape they are all converted into, so that mapping,
scoring, and reporting only ever deal with one format.

The flow through the program is:

    scanner output  ->  Finding (this module)  ->  mapping.py adds standards
                                               ->  report.py scores + renders

Everything here is a plain dataclass with no behaviour beyond small helpers,
which keeps the schema easy to read, test, and serialise to JSON.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.StrEnum):
    """How bad a finding is. Ordered from worst to least bad."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting: CRITICAL is 0, INFO is 4."""
        return list(Severity).index(self)

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Turn a scanner's severity label into a Severity.

        Scanners use different words for the same idea (Semgrep says
        "ERROR"/"WARNING", GitHub advisories say "moderate"), so known
        aliases are normalised here. Unknown values raise ValueError rather
        than being silently guessed.
        """
        normalised = value.strip().lower()
        aliases = {
            "error": cls.HIGH,
            "warning": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "note": cls.LOW,
            "informational": cls.INFO,
        }
        if normalised in aliases:
            return aliases[normalised]
        return cls(normalised)


class CheckStatus(enum.StrEnum):
    """The outcome of one checklist rule as a whole."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"  # could not be evaluated (e.g. no API token); not a failure
    ERROR = "error"  # the check itself broke; reported, never crashes the run


class ToolStatus(enum.StrEnum):
    """Whether an external scanner ran successfully."""

    OK = "ok"
    NOT_INSTALLED = "not_installed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class StandardRef:
    """A pointer to an entry in a security standard.

    framework is one of "OWASP", "CWE", or "NIST-SSDF"; id is the entry's
    identifier in that framework, e.g. "CWE-798" or "A05:2025".
    """

    framework: str
    id: str
    name: str = ""
    url: str = ""


@dataclass(frozen=True)
class Location:
    """Where a finding lives. All fields except path are optional.

    commit is set when a finding exists only in git history (e.g. a secret
    that was committed and later deleted).
    """

    path: str
    line: int | None = None
    end_line: int | None = None
    commit: str | None = None

    def __str__(self) -> str:
        text = self.path if self.line is None else f"{self.path}:{self.line}"
        if self.commit:
            text += f" (commit {self.commit[:7]})"
        return text


@dataclass(frozen=True)
class Finding:
    """One problem found in the scanned repository.

    Findings are immutable; enrichment steps (like adding standards in
    mapping.py) use dataclasses.replace() to produce a new copy.

    SECURITY: `evidence` must never contain a secret value. Scanner adapters
    are responsible for passing it through redaction.redact() first, and the
    Gitleaks adapter never reads the secret field at all.
    """

    rule_id: str  # the SAFECODE checklist rule, e.g. "SC-001"
    title: str  # short human-readable headline
    severity: Severity
    source: str  # what produced it: "semgrep", "gitleaks", "osv-scanner", "checklist"
    message: str  # what was found, in plain English
    location: Location | None = None  # None for repo-wide findings (e.g. missing SECURITY.md)
    source_rule_id: str = ""  # the scanner's own rule ID, e.g. Gitleaks' "aws-access-token"
    standards: tuple[StandardRef, ...] = ()
    why_it_matters: str = ""
    fix: str = ""
    evidence: str = ""  # short, already-redacted context

    @property
    def fingerprint(self) -> str:
        """A stable ID used to de-duplicate findings across scanners and runs."""
        loc = self.location
        parts = [
            self.rule_id,
            self.source_rule_id,
            loc.path if loc else "",
            str(loc.line) if loc and loc.line is not None else "",
            (loc.commit or "") if loc else "",
        ]
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class CheckResult:
    """The overall pass/fail status of one checklist rule."""

    rule_id: str
    status: CheckStatus
    summary: str = ""  # one line, e.g. "3 secrets found" or "skipped: no GitHub token"


@dataclass(frozen=True)
class ToolRun:
    """A record of one external scanner invocation, shown in the report so
    users can see what actually ran (and what did not)."""

    name: str
    status: ToolStatus
    version: str = ""
    detail: str = ""  # short error or skip reason; never contains secrets
    duration_s: float = 0.0


@dataclass
class ScanResult:
    """Everything one SAFECODE run produced. This is the input to report.py."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    tools: list[ToolRun] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # run-level caveats, e.g. "shallow clone"

    def add_findings(self, new: list[Finding]) -> None:
        """Append findings, dropping exact duplicates by fingerprint."""
        seen = {f.fingerprint for f in self.findings}
        for finding in new:
            if finding.fingerprint not in seen:
                self.findings.append(finding)
                seen.add(finding.fingerprint)

    def counts_by_severity(self) -> dict[Severity, int]:
        """Number of findings per severity, including zero counts, worst first."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered worst-first, then by file and line for stable output."""

        def key(f: Finding) -> tuple[int, str, int]:
            path = f.location.path if f.location else ""
            line = f.location.line if f.location and f.location.line else 0
            return (f.severity.rank, path, line)

        return sorted(self.findings, key=key)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serialisable view of the whole result."""
        data = asdict(self)
        for raw, finding in zip(data["findings"], self.findings):
            raw["fingerprint"] = finding.fingerprint
        return data
