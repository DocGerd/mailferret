import tomllib
from pathlib import Path

from click.testing import CliRunner

from mailferret import __version__
from mailferret.cli import main


def test_cli_reports_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_version_matches_pyproject() -> None:
    with (Path(__file__).parents[1] / "pyproject.toml").open("rb") as f:
        assert tomllib.load(f)["project"]["version"] == __version__
