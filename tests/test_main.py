"""Tests for configuration parsing and graceful tool failure."""

from pathlib import Path

import pytest

from safecode.main import main, parse_config
from safecode.scanners.base import run_tool
from safecode.schema import ToolStatus


class TestConfig:
    def test_reads_action_inputs_from_env(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("INPUT_FAIL-THRESHOLD", "c")
        monkeypatch.setenv("INPUT_COMMENT-ON-PR", "false")
        monkeypatch.setenv("INPUT_SEMGREP-CONFIG", "p/python, p/javascript")
        monkeypatch.setenv("INPUT_GITHUB-TOKEN", "ghs_example")
        config = parse_config([])
        assert config.path == tmp_path.resolve()
        assert config.fail_threshold == "C"
        assert config.comment_on_pr is False
        assert config.semgrep_configs == ("p/python", "p/javascript")
        assert config.github_token == "ghs_example"

    def test_token_not_in_repr(self, monkeypatch):
        monkeypatch.setenv("INPUT_GITHUB-TOKEN", "ghs_supersecretvalue")
        assert "ghs_supersecretvalue" not in repr(parse_config([]))

    def test_cli_overrides_env(self, monkeypatch):
        monkeypatch.setenv("INPUT_FAIL-THRESHOLD", "A")
        assert parse_config(["--fail-threshold", "off"]).fail_threshold == "off"

    def test_invalid_threshold_is_config_error(self, capsys):
        assert main(["--fail-threshold", "Z"]) == 2
        assert "fail-threshold" in capsys.readouterr().err

    def test_missing_path_is_config_error(self, tmp_path, capsys):
        assert main(["--path", str(tmp_path / "nope")]) == 2
        assert "does not exist" in capsys.readouterr().err


class TestRunTool:
    def test_missing_binary_is_reported_not_raised(self, tmp_path: Path):
        output = run_tool("definitely-not-a-real-scanner", ["--version"], cwd=tmp_path)
        assert output.run.status is ToolStatus.NOT_INSTALLED
        assert output.stdout == ""
