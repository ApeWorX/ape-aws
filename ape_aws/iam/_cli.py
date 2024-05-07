import click
from ape.cli import ape_cli_context

from ape_aws.client import iam_client


@click.group("iam")
def iam():
    """Manage AWS Admin information"""


@iam.command()
@ape_cli_context()
def list_admins(cli_ctx):
    cli_ctx.logger.success(f"Administrators: {iam_client.list_admins()}")


@iam.command()
@ape_cli_context()
def list_users(cli_ctx):
    cli_ctx.logger.success(f"Users: {iam_client.list_users()}")
