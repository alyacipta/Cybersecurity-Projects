"""
©AngelaMos | 2026
test_cli.py
"""

import re

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _clean(text: str) -> str:
    """
    Strip ANSI escape codes and lowercase
    """
    return _ANSI_RE.sub("", text).lower()


class TestCLICommands:
    """
    Test CLI help output and argument validation
    """

    def test_train_help_shows_csic_dir(
        self,
    ) -> None:
        """
        train --help shows csic-dir option
        """
        result = runner.invoke(
            app, ["train", "--help"]
        )
        assert result.exit_code == 0
        assert "csic-dir" in _clean(result.output)

    def test_train_help_shows_synthetic_options(
        self,
    ) -> None:
        """
        train --help shows synthetic normal and attack options
        """
        result = runner.invoke(
            app, ["train", "--help"]
        )
        assert result.exit_code == 0
        output = _clean(result.output)
        assert "synthetic-normal" in output
        assert "synthetic-attack" in output

    def test_train_invalid_csic_dir_fails(
        self,
    ) -> None:
        """
        train with nonexistent csic-dir exits with error
        """
        result = runner.invoke(
            app,
            [
                "train",
                "--csic-dir",
                "/nonexistent/csic",
                "--synthetic-normal",
                "0",
                "--synthetic-attack",
                "0",
            ],
        )
        assert result.exit_code != 0

    def test_replay_help(self) -> None:
        """
        replay --help exits cleanly and mentions log
        """
        result = runner.invoke(
            app, ["replay", "--help"]
        )
        assert result.exit_code == 0
        assert "log" in _clean(result.output)

    def test_serve_help(self) -> None:
        """
        serve --help exits cleanly and mentions host
        """
        result = runner.invoke(
            app, ["serve", "--help"]
        )
        assert result.exit_code == 0
        assert "host" in _clean(result.output)

    def test_config_help(self) -> None:
        """
        config --help exits cleanly
        """
        result = runner.invoke(
            app, ["config", "--help"]
        )
        assert result.exit_code == 0

    def test_health_help(self) -> None:
        """
        health --help exits cleanly
        """
        result = runner.invoke(
            app, ["health", "--help"]
        )
        assert result.exit_code == 0

    def test_replay_missing_log_fails(self) -> None:
        """
        replay with nonexistent log file exits with error
        """
        result = runner.invoke(
            app,
            [
                "replay",
                "--log-file",
                "/nonexistent/access.log",
            ],
        )
        assert result.exit_code != 0
