import click

from mailferret import __version__


@click.group()
@click.version_option(__version__, prog_name="mailferret")
def main() -> None:
    """Read-only IMAP access for MCP clients."""
