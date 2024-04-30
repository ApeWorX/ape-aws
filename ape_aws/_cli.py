import click

from ape_aws.admin._cli import admin
from ape_aws.kms._cli import kms


@click.group()
def cli():
    """Ape AWS CLI commands"""


cli.add_command(admin)
cli.add_command(kms)
