import click

from ape_aws.client import iam_client


@click.group("iam")
def iam():
    """Manage AWS Admin information"""


@iam.command()
def list_admins():
    click.echo(f"Administrators:\n{'\n'.join(iam_client.list_admins())}")


@iam.command()
def list_users():
    click.echo(f"Users:\n{'\n'.join(iam_client.list_users())}")
