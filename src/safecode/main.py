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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from safecode import __version__
from safecode.rules import DEFAULT_CHECKLIST, ChecklistError, Rule, load_rules
from safecode.schema import ScanResult

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
    # repr=False keeps the token out of any accidental print(config) or traceback.
    github_token: str = field(default="", repr=False)


# A step takes the run's config and rules and adds its findings, check
# results, and tool records to the shared ScanResult. Steps must not raise:
# each one catches its own failures and records them on the result instead.
Step = Callable[[Config, dict[str, Rule], ScanResult], None]

# Scanner and hygiene steps are registered here as they are implemented
# (phase 2: Gitleaks, OSV-Scanner, Semgrep; phase 3: hygiene checks).
STEPS: list[Step] = []


def run(config: Config, rules: dict[str, Rule]) -> ScanResult:
    """Execute every step against the target and return the merged result."""
    result = ScanResult(target=str(config.path))
    for step in STEPS:
        step(config, rules, result)
    return result


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

    if config.json_out:
        config.json_out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")

    # Placeholder output until report.py lands in phase 2.
    counts = ", ".join(f"{sev}: {n}" for sev, n in result.counts_by_severity().items())
    print(f"SAFECODE {__version__} scanned {config.path}")
    print(f"{len(rules)} checklist rules loaded; {len(STEPS)} scan steps registered")
    print(f"Findings by severity: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
