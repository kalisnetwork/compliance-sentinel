"""Command-line interface for Compliance Sentinel."""

import click
from compliance_sentinel.cli.hook_commands import hooks_cli
from compliance_sentinel.cli.analyze_command import analyze
from compliance_sentinel.cli.config_commands import config_group


@click.group()
@click.version_option()
def cli():
    """Compliance Sentinel - Proactive Security and Compliance Enforcement System."""
    pass


# Add commands
cli.add_command(analyze)
cli.add_command(config_group)
cli.add_command(hooks_cli)


if __name__ == '__main__':
    cli()