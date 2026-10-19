"""Tests for the repo-hygiene checks (SC-004 to SC-007), against temporary directories."""

import json
import subprocess
from pathlib import Path

import pytest

from safecode import checklist
from safecode.checklist import HygieneContext
from safecode.rules import DEFAULT_CHECKLIST, load_rules
from safecode.schema import CheckStatus


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_CHECKLIST)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def run(rules, rule_id, target, **ctx):
    rule = rules[rule_id]
    return checklist.HYGIENE_CHECKS[rule.check_type](rule, HygieneContext(target=target, **ctx))


PKG = json.dumps({"dependencies": {"lodash": "^4.17.21"}})


class TestLockfile:
    def test_no_manifests_passes(self, rules, tmp_path):
        outcome = run(rules, "SC-004", write(tmp_path, {"main.py": ""}))
        assert outcome.status is CheckStatus.PASSED
        assert outcome.summary == "no dependency manifests found"

    def test_package_json_without_lockfile_fails(self, rules, tmp_path):
        outcome = run(rules, "SC-004", write(tmp_path, {"web/package.json": PKG}))
        assert outcome.status is CheckStatus.FAILED
        [finding] = outcome.findings
        assert finding.location.path == "web/package.json"
        assert "npm install" in finding.fix

    @pytest.mark.parametrize("lockfile", ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"])
    def test_any_npm_lockfile_counts(self, rules, tmp_path, lockfile):
        assert run(rules, "SC-004", write(tmp_path, {"package.json": PKG, lockfile: ""})).status is CheckStatus.PASSED

    def test_workspace_lockfile_in_parent_counts(self, rules, tmp_path):
        target = write(tmp_path, {"package.json": PKG, "package-lock.json": "", "packages/ui/package.json": PKG})
        assert run(rules, "SC-004", target).status is CheckStatus.PASSED

    def test_manifest_without_dependencies_is_ignored(self, rules, tmp_path):
        target = write(tmp_path, {"package.json": json.dumps({"name": "x", "scripts": {}}),
                                  "pyproject.toml": '[project]\nname = "x"\n', "go.mod": "module x\n\ngo 1.22\n"})
        assert run(rules, "SC-004", target).summary == "no dependency manifests found"

    def test_vendored_manifests_are_skipped(self, rules, tmp_path):
        target = write(tmp_path, {"node_modules/lib/package.json": PKG, ".venv/x/requirements.txt": "requests\n"})
        assert run(rules, "SC-004", target).status is CheckStatus.PASSED

    def test_pyproject_accepts_pinned_requirements_as_lock(self, rules, tmp_path):
        pyproject = '[project]\nname = "x"\ndependencies = ["requests>=2"]\n'
        assert run(rules, "SC-004", write(tmp_path, {"pyproject.toml": pyproject})).status is CheckStatus.FAILED
        target = write(tmp_path, {"requirements.txt": "requests==2.32.3\n"})
        assert run(rules, "SC-004", target).status is CheckStatus.PASSED

    def test_unpinned_requirements_are_listed_with_first_line(self, rules, tmp_path):
        target = write(tmp_path, {"requirements.txt": (
            "# comment\n"
            "-r base.txt\n"
            "--index-url https://pypi.org/simple\n"
            "django==5.1.2\n"
            "requests>=2.0  # trailing comment\n"
            "numpy\n"
            "pyyaml==6.0.3 \\\n    --hash=sha256:abc\n"
            "attrs[tests]~=23.0 ; python_version >= '3.11'\n"
            "mylib @ https://example.com/mylib-1.0.tar.gz\n"
            "./local-package\n"
        )})
        [finding] = run(rules, "SC-004", target).findings
        assert "3 package(s)" in finding.message
        assert "requests, numpy, attrs" in finding.message
        assert finding.location.line == 5

    def test_go_mod_with_requires_needs_go_sum(self, rules, tmp_path):
        target = write(tmp_path, {"go.mod": "module x\n\nrequire github.com/a/b v1.0.0\n"})
        assert run(rules, "SC-004", target).status is CheckStatus.FAILED


class TestGitignore:
    def test_missing_gitignore(self, rules, tmp_path):
        [finding] = run(rules, "SC-005", tmp_path).findings
        assert finding.title == "No .gitignore file"
        assert finding.location is None

    def test_reports_missing_patterns(self, rules, tmp_path):
        target = write(tmp_path, {".gitignore": "node_modules/\n.env\n"})
        [finding] = run(rules, "SC-005", target).findings
        assert "*.pem, *.key, credentials*" in finding.message

    def test_equivalent_patterns_are_accepted(self, rules, tmp_path):
        target = write(tmp_path, {".gitignore": "/.env*\n**/*.pem\n*.key\ncredentials*\n"})
        assert run(rules, "SC-005", target).status is CheckStatus.PASSED

    def test_negation_un_ignores(self, rules, tmp_path):
        target = write(tmp_path, {".gitignore": ".env\n*.pem\n*.key\ncredentials*\n!.env\n"})
        [finding] = run(rules, "SC-005", target).findings
        assert finding.message.endswith("cover: .env.")

    def test_subdirectory_pattern_does_not_protect_root(self, rules, tmp_path):
        target = write(tmp_path, {".gitignore": "config/.env\n*.pem\n*.key\ncredentials*\n"})
        assert ".env" in run(rules, "SC-005", target).findings[0].message

    def test_committed_secret_file_is_reported(self, rules, tmp_path):
        target = write(tmp_path, {".gitignore": ".env\n*.pem\n*.key\ncredentials*\n",
                                  "deploy/server.pem": "fake", ".env.example": "API_KEY=", "app.py": ""})
        subprocess.run(["git", "init", "-q", str(target)], check=True)
        subprocess.run(["git", "-C", str(target), "add", "-f", "."], check=True)
        findings = run(rules, "SC-005", target).findings
        assert [f.location.path for f in findings] == ["deploy/server.pem"]  # .env.example is fine
        assert "git rm --cached deploy/server.pem" in findings[0].fix


class TestFileExists:
    @pytest.mark.parametrize("path", ["SECURITY.md", ".github/SECURITY.md", "docs/security.md"])
    def test_found_in_any_location_any_case(self, rules, tmp_path, path):
        outcome = run(rules, "SC-006", write(tmp_path, {path: "Report to security@example.com"}))
        assert outcome.status is CheckStatus.PASSED

    def test_missing(self, rules, tmp_path):
        outcome = run(rules, "SC-006", tmp_path)
        assert outcome.status is CheckStatus.FAILED
        assert outcome.findings[0].title == "Missing SECURITY.md"


class FakeGitHub:
    """Stands in for GitHubClient: returns canned (status, data) per API path."""

    def __init__(self, responses):
        self.repo = "octo/app"
        self.responses = responses
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        return self.responses.get(path, (404, None))


BRANCH = "/repos/octo/app/branches/main"
RULES = "/repos/octo/app/rules/branches/main"


class TestBranchProtection:
    def test_skipped_without_repository(self, rules, tmp_path):
        assert run(rules, "SC-007", tmp_path).status is CheckStatus.SKIPPED

    def test_classic_protection_passes(self, rules, tmp_path):
        gh = FakeGitHub({BRANCH: (200, {"protected": True}), RULES: (200, [])})
        outcome = run(rules, "SC-007", tmp_path, github=gh, default_branch="main")
        assert (outcome.status, outcome.summary) == (CheckStatus.PASSED, "main is protected")

    def test_ruleset_requiring_prs_passes(self, rules, tmp_path):
        gh = FakeGitHub({BRANCH: (200, {"protected": False}), RULES: (200, [{"type": "pull_request"}])})
        outcome = run(rules, "SC-007", tmp_path, github=gh, default_branch="main")
        assert outcome.summary == "main is protected (pull requests required)"

    def test_unprotected_fails(self, rules, tmp_path):
        gh = FakeGitHub({BRANCH: (200, {"protected": False}), RULES: (200, [{"type": "creation"}])})
        outcome = run(rules, "SC-007", tmp_path, github=gh, default_branch="main")
        assert outcome.status is CheckStatus.FAILED
        assert outcome.findings[0].title == "Default branch main is not protected"

    def test_default_branch_looked_up_when_unknown(self, rules, tmp_path):
        gh = FakeGitHub({"/repos/octo/app": (200, {"default_branch": "main"}), BRANCH: (200, {"protected": True})})
        assert run(rules, "SC-007", tmp_path, github=gh).status is CheckStatus.PASSED
        assert gh.calls[0] == "/repos/octo/app"

    @pytest.mark.parametrize("status", [0, 403, 404, 500])
    def test_api_problems_skip_instead_of_failing(self, rules, tmp_path, status):
        gh = FakeGitHub({BRANCH: (status, None)})
        outcome = run(rules, "SC-007", tmp_path, github=gh, default_branch="main")
        assert outcome.status is CheckStatus.SKIPPED
