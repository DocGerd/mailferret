from click.testing import CliRunner

from mailferret import __version__
from mailferret.cli import main


def test_cli_reports_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
