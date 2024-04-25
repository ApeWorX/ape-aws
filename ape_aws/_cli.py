import click


@click.group()
def cli():
    """Ape AWS CLI commands"""


cli.add_command()
