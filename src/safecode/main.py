"""SAFECODE entry point: read settings, run every check, emit the results.

Runs the same way in two places:

* Inside the GitHub Action. Settings arrive as INPUT_* environment variables
  (GitHub sets one per input in action.yml) and the repo is mounted at
  $GITHUB_WORKSPACE.
* Locally, for development: `python -m safecode --path examples/vulnerable-app`.
  Command-line flags take precedence over environment variables.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from safecode import __version__, checklist, github, mapping, report
from safecode.rules import DEFAULT_CHECKLIST, ChecklistError, Rule, load_rules
from safecode.scanners import gitleaks, osv, semgrep
from safecode.scanners.base import ScanOutput
from safecode.schema import CheckResult, CheckStatus, ScanResult, ToolRun, ToolStatus

FAIL_THRESHOLDS = ("off", "A", "B", "C", "D")


@dataclass(frozen=True)
class Config:
    """Settings for one run, after parsing and validation."""

    path: Path
    checklist: Path = DEFAULT_CHECKLIST
    fail_threshold: str = "off"  # fail the job if the grade is worse than this letter
    comment_on_pr: bool = True
    semgrep_configs: tuple[str, ...] = ()  # extra Semgrep configs on top of SAFECODE's own rules
    json_out: Path | None = None
    report_out: Path | None = None
    repo: str = ""  # "owner/name"; defaults to $GITHUB_REPOSITORY inside Actions
    # repr=False keeps the token out of any accidental print(config) or traceback.
    github_token: str = field(default="", repr=False)


# --- Scan steps ----------------------------------------------------------------
#
# Each scanner adapter is called with the enabled checklist rules of its
# check type and returns a ScanOutput. _run_scanner() does the shared work:
# catching crashes, enriching findings with standards, and turning the tool's
# status into a pass/fail/skipped/error result for each rule.

Scanner = Callable[[Config, list[Rule], dict[str, Rule]], ScanOutput]


def _gitleaks(config: Config, enabled: list[Rule], rules: dict[str, Rule]) -> ScanOutput:
    return gitleaks.scan(config.path, enabled[0].id, enabled[0].severity)


def _osv(config: Config, enabled: list[Rule], rules: dict[str, Rule]) -> ScanOutput:
    return osv.scan(config.path, enabled[0].id, enabled[0].severity)


def _semgrep(config: Config, enabled: list[Rule], rules: dict[str, Rule]) -> ScanOutput:
    return semgrep.scan(config.path, mapping.cwe_to_rule(rules), config.semgrep_configs)


# check type -> (tool name, adapter). One tool run serves every rule of that type.
SCANNERS: dict[str, tuple[str, Scanner]] = {
    "gitleaks": (gitleaks.TOOL, _gitleaks),
    "osv": (osv.TOOL, _osv),
    "semgrep": (semgrep.TOOL, _semgrep),
}


def run(config: Config, rules: dict[str, Rule]) -> ScanResult:
    """Execute every check against the target and return the merged result."""
    result = ScanResult(target=str(config.path))

    for check_type, (tool_name, scanner) in SCANNERS.items():
        _run_scanner(config, rules, result, check_type, tool_name, scanner)

    context = _hygiene_context(config)
    for rule in rules.values():
        if rule.check_type in checklist.HYGIENE_CHECKS:
            _run_hygiene(rule, context, rules, result)

    # Present checks in checklist order regardless of which step produced them.
    order = {rule_id: index for index, rule_id in enumerate(rules)}
    result.checks.sort(key=lambda c: order.get(c.rule_id, len(order)))
    return result


def _run_scanner(config: Config, rules: dict[str, Rule], result: ScanResult,
                 check_type: str, tool_name: str, scanner: Scanner) -> None:
    """Run one scanner for all rules of check_type and record everything on result."""
    of_type = [rule for rule in rules.values() if rule.check_type == check_type]
    enabled = [rule for rule in of_type if rule.enabled]
    for rule in of_type:
        if not rule.enabled:
            result.checks.append(CheckResult(rule.id, CheckStatus.SKIPPED, "disabled in checklist"))
    if not enabled:
        return

    try:
        output = scanner(config, enabled, rules)
    except Exception as exc:  # noqa: BLE001 - one broken adapter must not stop the other scanners
        traceback.print_exc(file=sys.stderr)
        output = ScanOutput(ToolRun(tool_name, ToolStatus.ERROR, detail=f"internal error: {type(exc).__name__}"))

    result.tools.append(output.run)
    result.notes.extend(output.notes)

    # Keep findings for enabled rules, plus "extra" findings that belong to no rule.
    findings = [
        mapping.enrich(f, rules)
        for f in output.findings
        if (f.rule_id in rules and rules[f.rule_id].enabled) or f.rule_id not in rules
    ]
    result.add_findings(findings)

    for rule in enabled:
        count = sum(1 for f in result.findings if f.rule_id == rule.id)
        result.checks.append(_check_from_tool(rule.id, output.run, count))


def _hygiene_context(config: Config) -> checklist.HygieneContext:
    """Collect what the hygiene checks need: the target and, if known, the GitHub repo."""
    payload_repo = github.event_payload().get("repository") or {}
    return checklist.HygieneContext(
        target=config.path,
        github=github.client_from_env(config.repo, config.github_token),
        default_branch=str(payload_repo.get("default_branch") or ""),
    )


def _run_hygiene(rule: Rule, context: checklist.HygieneContext, rules: dict[str, Rule], result: ScanResult) -> None:
    """Run one hygiene check and record its outcome; a crash becomes an ERROR result."""
    if not rule.enabled:
        result.checks.append(CheckResult(rule.id, CheckStatus.SKIPPED, "disabled in checklist"))
        return
    try:
        outcome = checklist.HYGIENE_CHECKS[rule.check_type](rule, context)
    except Exception as exc:  # noqa: BLE001 - a broken check must not stop the others
        traceback.print_exc(file=sys.stderr)
        result.checks.append(CheckResult(rule.id, CheckStatus.ERROR, f"internal error: {type(exc).__name__}"))
        return
    result.add_findings([mapping.enrich(f, rules) for f in outcome.findings])
    result.checks.append(CheckResult(rule.id, outcome.status, outcome.summary))


def _check_from_tool(rule_id: str, run: ToolRun, count: int) -> CheckResult:
    """Translate a tool's outcome into the rule's pass/fail status."""
    if run.status is ToolStatus.OK:
        if count:
            return CheckResult(rule_id, CheckStatus.FAILED, f"{count} finding{'s' if count != 1 else ''}")
        return CheckResult(rule_id, CheckStatus.PASSED, run.detail or "no issues found")
    if run.status in (ToolStatus.NOT_INSTALLED, ToolStatus.SKIPPED):
        return CheckResult(rule_id, CheckStatus.SKIPPED, f"not checked: {run.detail}")
    return CheckResult(rule_id, CheckStatus.ERROR, f"{run.name} failed: {run.detail}")


def _input(name: str, default: str = "") -> str:
    """Read a GitHub Action input. GitHub exposes `fail-threshold` as INPUT_FAIL-THRESHOLD."""
    return os.environ.get(f"INPUT_{name.upper()}", default).strip()


def _parse_bool(value: str, name: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    raise ValueError(f"{name} must be true or false, got {value!r}")


def parse_config(argv: list[str] | None = None) -> Config:
    """Build a Config from command-line flags, falling back to Action inputs."""
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))

    parser = argparse.ArgumentParser(prog="safecode", description="Security report and grade for a repository.")
    parser.add_argument("--path", default=_input("scan-path", "."), help="directory to scan (default: .)")
    parser.add_argument("--checklist", type=Path, default=DEFAULT_CHECKLIST, help="checklist YAML to use")
    parser.add_argument(
        "--fail-threshold",
        default=_input("fail-threshold", "off"),
        help="fail if the grade is worse than this: A, B, C, D, or off (default)",
    )
    parser.add_argument("--comment-on-pr", default=_input("comment-on-pr", "true"))
    parser.add_argument(
        "--semgrep-config",
        action="append",
        default=None,
        help="extra Semgrep config (repeatable), e.g. p/python",
    )
    parser.add_argument("--json-out", type=Path, default=None, help="also write raw results as JSON here")
    parser.add_argument("--report-out", type=Path, default=None, help="also write the Markdown report here")
    parser.add_argument("--repo", default="", help="GitHub owner/name for the branch-protection check "
                                                   "(default: $GITHUB_REPOSITORY; token from $GITHUB_TOKEN)")
    parser.add_argument("--version", action="version", version=f"safecode {__version__}")
    args = parser.parse_args(argv)

    semgrep_configs = args.semgrep_config
    if semgrep_configs is None:
        # The Action input is a single string; allow comma/newline-separated values.
        raw = _input("semgrep-config").replace(",", "\n")
        semgrep_configs = [line.strip() for line in raw.splitlines() if line.strip()]

    # Validated here rather than via argparse `choices`, because argparse does
    # not check defaults, and our default comes from an environment variable.
    fail_threshold = args.fail_threshold.strip()
    fail_threshold = "off" if fail_threshold.lower() in {"", "off", "none"} else fail_threshold.upper()
    if fail_threshold not in FAIL_THRESHOLDS:
        raise ValueError(f"fail-threshold must be one of {', '.join(FAIL_THRESHOLDS)}, got {args.fail_threshold!r}")

    path = Path(args.path)
    if not path.is_absolute():
        path = workspace / path

    return Config(
        path=path.resolve(),
        checklist=args.checklist,
        fail_threshold=fail_threshold,
        comment_on_pr=_parse_bool(args.comment_on_pr, "comment-on-pr"),
        semgrep_configs=tuple(semgrep_configs),
        json_out=args.json_out,
        report_out=args.report_out,
        repo=args.repo,
        github_token=_input("github-token") or os.environ.get("GITHUB_TOKEN", ""),
    )


def main(argv: list[str] | None = None) -> int:
    """Run SAFECODE. Returns the process exit code."""
    try:
        config = parse_config(argv)
        rules = load_rules(config.checklist)
    except (ValueError, ChecklistError) as exc:
        # Configuration mistakes are the user's to fix, so print a clear message, not a traceback.
        print(f"safecode: configuration error: {exc}", file=sys.stderr)
        return 2

    if not config.path.is_dir():
        print(f"safecode: scan path does not exist or is not a directory: {config.path}", file=sys.stderr)
        return 2

    result = run(config, rules)
    markdown = report.render(result, rules, repo_name=os.environ.get("GITHUB_REPOSITORY", config.path.name))

    if config.json_out:
        config.json_out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    if config.report_out:
        config.report_out.write_text(markdown, encoding="utf-8")

    # In GitHub Actions, the job summary file shows on the workflow run page.
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write(markdown)

    _print(markdown)
    return 0


def _print(text: str) -> None:
    """Print to stdout, tolerating consoles that can't show emoji (e.g. legacy Windows code pages)."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii"))


if __name__ == "__main__":
    sys.exit(main())
