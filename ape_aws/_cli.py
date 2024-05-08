import click

from ape_aws.iam._cli import iam
from ape_aws.kms._cli import kms


@click.group()
def cli():
    """Ape AWS CLI commands"""


cli.add_command(iam)
cli.add_command(kms)
