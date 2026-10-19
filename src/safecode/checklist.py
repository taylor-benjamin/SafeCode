"""Repo-hygiene checks: practices that no scanner looks for.

    lockfile           SC-004  every dependency manifest has a lockfile / exact pins
    gitignore          SC-005  .gitignore blocks secret-bearing files; none are committed
    file_exists        SC-006  SECURITY.md (or any configured file) exists
    branch_protection  SC-007  the default branch is protected (GitHub API)

Each check takes a Rule (for its options and default severity) and a
HygieneContext, and returns a CheckOutcome. Checks are pure apart from
reading the filesystem, running `git ls-files`, and (for branch protection)
calling the GitHub API, so they are easy to test against temporary directories.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from safecode.github import NETWORK_ERROR, GitHubClient
from safecode.rules import Rule
from safecode.schema import CheckStatus, Finding, Location

# Directories that hold third-party or generated code; their manifests aren't the repo's own.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "third_party", ".venv", "venv", "env", "__pycache__",
    ".tox", ".nox", "dist", "build", "target", ".tools", "site-packages", "bower_components",
})


@dataclass
class HygieneContext:
    """Everything a hygiene check may need beyond its rule."""

    target: Path
    github: GitHubClient | None = None
    default_branch: str = ""  # known from the Actions event payload; looked up via API otherwise


@dataclass
class CheckOutcome:
    status: CheckStatus
    summary: str
    findings: list[Finding] = field(default_factory=list)


HygieneCheck = Callable[[Rule, HygieneContext], CheckOutcome]


def _finding(rule: Rule, title: str, message: str, path: str | None = None, line: int | None = None,
             fix: str = "") -> Finding:
    return Finding(
        rule_id=rule.id,
        title=title,
        severity=rule.severity,
        source="checklist",
        message=message,
        location=Location(path, line) if path else None,
        source_rule_id=f"{rule.check_type}:{path or 'repo'}",
        fix=fix,
    )


def _summarise(findings: list[Finding], passed: str) -> CheckOutcome:
    if findings:
        count = len(findings)
        return CheckOutcome(CheckStatus.FAILED, f"{count} finding{'s' if count != 1 else ''}", findings)
    return CheckOutcome(CheckStatus.PASSED, passed)


def _walk(target: Path):
    """Yield (directory, filenames) under target, skipping third-party and generated directories."""
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        yield Path(dirpath), set(filenames)


def _rel(path: Path, target: Path) -> str:
    return path.relative_to(target).as_posix()


# --- SC-004: lockfiles and pinned versions ------------------------------------------

@dataclass(frozen=True)
class _Ecosystem:
    manifest: str
    lockfiles: tuple[str, ...]
    fix: str
    # Lockfiles for workspaces/monorepos often live in a parent directory.
    lock_in_parents: bool = True


ECOSYSTEMS = (
    _Ecosystem("package.json",
               ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"),
               "Run `npm install` (or yarn / pnpm / bun) and commit the lockfile it generates."),
    _Ecosystem("pyproject.toml", ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"),
               "Generate a lockfile (`uv lock` or `poetry lock`), or a fully pinned requirements.txt "
               "(`pip-compile` / `uv pip compile`), and commit it."),
    _Ecosystem("Pipfile", ("Pipfile.lock",), "Run `pipenv lock` and commit Pipfile.lock.", lock_in_parents=False),
    _Ecosystem("Gemfile", ("Gemfile.lock",), "Run `bundle install` and commit Gemfile.lock.", lock_in_parents=False),
    _Ecosystem("composer.json", ("composer.lock",), "Run `composer install` and commit composer.lock."),
    _Ecosystem("Cargo.toml", ("Cargo.lock",), "Run `cargo generate-lockfile` and commit Cargo.lock."),
    _Ecosystem("go.mod", ("go.sum",), "Run `go mod tidy` and commit go.sum.", lock_in_parents=False),
)

REQUIREMENTS_FIX = (
    "Pin every package to an exact version with == (for example requests==2.32.3), "
    "or generate the file with `pip-compile` / `uv pip compile`."
)
_MAX_LISTED = 5


def check_lockfile(rule: Rule, ctx: HygieneContext) -> CheckOutcome:
    """SC-004: each manifest has a lockfile; each requirements*.txt pins exact versions."""
    findings: list[Finding] = []
    manifests = 0
    all_files = {directory: names for directory, names in _walk(ctx.target)}

    def has_lock(directory: Path, eco: _Ecosystem) -> bool:
        candidates = [directory, *directory.parents] if eco.lock_in_parents else [directory]
        for candidate in candidates:
            if candidate != ctx.target and ctx.target not in candidate.parents:
                break  # don't look above the scanned directory
            names = all_files.get(candidate, set())
            if any(lock in names for lock in eco.lockfiles):
                return True
            # pylock.<name>.toml (PEP 751) and a fully pinned requirements.txt also count for Python.
            if eco.manifest == "pyproject.toml" and any(
                re.fullmatch(r"pylock\..+\.toml", n) or (_is_requirements(n) and not _unpinned(candidate / n))
                for n in names
            ):
                return True
        return False

    for directory, names in all_files.items():
        for eco in ECOSYSTEMS:
            path = directory / eco.manifest
            if eco.manifest not in names or not _declares_dependencies(path):
                continue
            manifests += 1
            if not has_lock(directory, eco):
                findings.append(_finding(
                    rule, f"No lockfile for {eco.manifest}",
                    f"{_rel(path, ctx.target)} declares dependencies but no lockfile ({', '.join(eco.lockfiles[:3])}…) "
                    "was found, so each install may pick up different versions.",
                    path=_rel(path, ctx.target), fix=eco.fix,
                ))

        for name in sorted(n for n in names if _is_requirements(n)):
            manifests += 1
            path = directory / name
            unpinned = _unpinned(path)
            if unpinned:
                listed = ", ".join(pkg for pkg, _ in unpinned[:_MAX_LISTED])
                if len(unpinned) > _MAX_LISTED:
                    listed += f", and {len(unpinned) - _MAX_LISTED} more"
                findings.append(_finding(
                    rule, f"Unpinned dependencies in {name}",
                    f"{len(unpinned)} package(s) are not pinned to an exact version: {listed}.",
                    path=_rel(path, ctx.target), line=unpinned[0][1], fix=REQUIREMENTS_FIX,
                ))

    if not manifests:
        return CheckOutcome(CheckStatus.PASSED, "no dependency manifests found")
    return _summarise(findings, f"{manifests} manifest(s) checked, all locked")


def _is_requirements(name: str) -> bool:
    return bool(re.fullmatch(r"requirements([-_.].+)?\.txt", name))


def _declares_dependencies(path: Path) -> bool:
    """Only manifests that actually pull in dependencies need a lockfile."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return True  # can't tell; err on the side of checking
        return isinstance(data, dict) and any(data.get(k) for k in ("dependencies", "devDependencies"))
    if path.name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return True
        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        return bool(data.get("project", {}).get("dependencies")) or any(k != "python" for k in poetry)
    if path.name == "go.mod":
        return re.search(r"^\s*require\b", text, re.MULTILINE) is not None
    return True


def _unpinned(path: Path) -> list[tuple[str, int]]:
    """(package, line number) for each requirement in a requirements file not pinned with ==."""
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    unpinned = []
    logical, start = "", 0
    for number, raw in enumerate(raw_lines, start=1):
        if not logical:
            start = number
        if raw.rstrip().endswith("\\"):  # line continuation, used with --hash
            logical += raw.rstrip()[:-1] + " "
            continue
        line, logical = (logical + raw).split(" #")[0].strip(), ""
        if not line or line.startswith("#") or line.startswith("-"):
            continue  # comments, and options like -r, -c, -e, --index-url
        requirement = line.split(";")[0].split()[0]  # drop environment markers and inline --hash options
        if requirement.startswith((".", "/")) or "://" in requirement or " @ " in line:
            continue  # local paths and direct URL references are fixed by definition
        if "==" not in requirement:
            unpinned.append((re.split(r"[<>=!~\[]", requirement)[0], start))
    return unpinned


# --- SC-005: .gitignore ----------------------------------------------------------------

def check_gitignore(rule: Rule, ctx: HygieneContext) -> CheckOutcome:
    """SC-005: .gitignore covers the configured patterns, and no matching file is committed."""
    patterns = [str(p) for p in rule.check_options.get("patterns", [])]
    tracked_patterns = [str(p) for p in rule.check_options.get("tracked", [])]
    findings: list[Finding] = []

    gitignore = ctx.target / ".gitignore"
    try:
        lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = None

    if lines is None:
        findings.append(_finding(
            rule, "No .gitignore file",
            "The repository has no .gitignore, so nothing stops secret files from being committed by accident.",
            fix=f"Create a .gitignore containing at least: {', '.join(patterns)}.",
        ))
    else:
        missing = [p for p in patterns if not _ignored(_probe_name(p), lines)]
        if missing:
            findings.append(_finding(
                rule, ".gitignore doesn't exclude secret files",
                f".gitignore does not cover: {', '.join(missing)}.",
                path=".gitignore", fix=f"Add these lines to .gitignore: {', '.join(missing)}.",
            ))

    for path in _tracked_files(ctx.target):
        name = path.rsplit("/", 1)[-1]
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in tracked_patterns):
            findings.append(_finding(
                rule, "Sensitive file is committed",
                f"{path} is tracked by git. Files like this usually hold secrets or private keys.",
                path=path,
                fix=f"Remove it from git with `git rm --cached {path}`, add it to .gitignore, and rotate "
                    "any credentials it contained (they remain in git history).",
            ))

    return _summarise(findings, ".gitignore covers secret files; none are committed")


def _probe_name(pattern: str) -> str:
    """A concrete filename a pattern should match: '*.pem' -> 'safecode-probe.pem'."""
    return pattern.strip("/").replace("**/", "").replace("*", "safecode-probe")


def _ignored(name: str, gitignore_lines: list[str]) -> bool:
    """Whether a root-level file would be ignored by these .gitignore lines.

    A deliberately small subset of gitignore semantics: wildcards, a leading
    "/" or "**/", and "!" negation (last match wins). Patterns that name a
    subdirectory ("config/.env") don't protect a root-level file and are skipped.
    """
    ignored = False
    for raw in gitignore_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        line = line.removeprefix("!").removeprefix("/").removeprefix("**/").rstrip("/")
        if "/" in line:
            continue
        if fnmatch.fnmatchcase(name, line):
            ignored = not negate
    return ignored


def _tracked_files(target: Path) -> list[str]:
    """Files git tracks under target ([] if target isn't in a git repo or git is missing)."""
    try:
        completed = subprocess.run(["git", "-C", str(target), "ls-files", "-z"], capture_output=True,
                                   timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    return [p for p in completed.stdout.decode("utf-8", errors="replace").split("\0") if p]


# --- SC-006: required files -----------------------------------------------------------

def check_file_exists(rule: Rule, ctx: HygieneContext) -> CheckOutcome:
    """SC-006: at least one of the configured paths exists (case-insensitive, like GitHub)."""
    paths = [str(p) for p in rule.check_options.get("paths", [])]
    for wanted in paths:
        parent = ctx.target / Path(wanted).parent
        try:
            names = {p.name.lower(): p for p in parent.iterdir() if p.is_file()}
        except OSError:
            continue
        if Path(wanted).name.lower() in names:
            return CheckOutcome(CheckStatus.PASSED, f"found {_rel(names[Path(wanted).name.lower()], ctx.target)}")

    listed = " or ".join(paths)
    return _summarise([_finding(rule, f"Missing {Path(paths[0]).name if paths else 'required file'}",
                                f"None of these files exist: {listed}.")], "")


# --- SC-007: branch protection ----------------------------------------------------------

# Ruleset rule types that protect a branch against unreviewed or destructive pushes.
PROTECTIVE_RULES = frozenset({"pull_request", "non_fast_forward", "deletion", "required_status_checks", "update"})


def check_branch_protection(rule: Rule, ctx: HygieneContext) -> CheckOutcome:
    """SC-007: the default branch has classic branch protection or an active ruleset.

    Uses two endpoints readable with the default Actions token (contents:read):
    GET /branches/{branch} for the `protected` flag, and GET /rules/branches/{branch}
    for rulesets. The detailed /protection endpoint would need an admin token.
    """
    gh = ctx.github
    if gh is None:
        return CheckOutcome(CheckStatus.SKIPPED, "not checked: no GitHub repository (runs automatically in Actions)")

    branch = ctx.default_branch
    if not branch:
        status, repo = gh.get(f"/repos/{gh.repo}")
        if status != 200 or not isinstance(repo, dict) or not repo.get("default_branch"):
            return CheckOutcome(CheckStatus.SKIPPED, f"not checked: couldn't read repository ({_describe(status)})")
        branch = repo["default_branch"]

    status, info = gh.get(f"/repos/{gh.repo}/branches/{quote(branch, safe='')}")
    if status != 200 or not isinstance(info, dict):
        return CheckOutcome(CheckStatus.SKIPPED, f"not checked: couldn't read branch {branch} ({_describe(status)})")

    status, rules = gh.get(f"/repos/{gh.repo}/rules/branches/{quote(branch, safe='')}")
    rule_types = {r.get("type") for r in rules if isinstance(r, dict)} if status == 200 and isinstance(rules, list) else set()

    if info.get("protected") or rule_types & PROTECTIVE_RULES:
        detail = " (pull requests required)" if "pull_request" in rule_types else ""
        return CheckOutcome(CheckStatus.PASSED, f"{branch} is protected{detail}")

    return _summarise([_finding(
        rule, f"Default branch {branch} is not protected",
        f"{branch} has no branch protection rule or ruleset, so anyone with write access can push to it "
        "directly, without review.",
    )], "")


def _describe(status: int) -> str:
    if status == NETWORK_ERROR:
        return "network error"
    if status in (401, 403, 404):
        return f"HTTP {status}: the token may lack permission"
    return f"HTTP {status}"


HYGIENE_CHECKS: dict[str, HygieneCheck] = {
    "lockfile": check_lockfile,
    "gitignore": check_gitignore,
    "file_exists": check_file_exists,
    "branch_protection": check_branch_protection,
}
