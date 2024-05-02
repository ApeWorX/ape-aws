import click

from ape_aws.accounts import KmsAccount, AwsAccountContainer
from ape_aws.client import kms_client, CreateKey, DeleteKey
from ape.cli import ape_cli_context


ADMIN_KEY_POLICY = """{
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [{
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {"AWS": "{arn}"},
        "Action": "kms:*",
        "Resource": "*"
    }]
}"""

USER_KEY_POLICY = """{
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [{
        "Sid": "Allow use of the key",
        "Effect": "Allow",
        "Principal": {"AWS": "{arn}"},
        "Action": ["kms:Sign", "kms:Verify"],
        "Resource": "*"
    }]
}"""


@click.group("kms")
def kms():
    """Manage AWS KMS keys"""


@kms.command(name="create")
@ape_cli_context()
@click.option(
    "-a",
    "--admin",
    "administrators",
    multiple=True,
    help="Apply key policy to a list of administrators if applicable, ex. -a A1, -a A2",
    metavar='list[str]',
)
@click.option(
    "-u",
    "--user",
    "users",
    multiple=True,
    help="Apply key policy to a list of users if applicable, ex. -u U1, -u U2",
    metavar='list[str]',
)
@click.option(
    "-t",
    "--tag",
    "tags",
    multiple=True,
    help="Apply tags to the newly created KMS key, ex. -t k1=v1 -t k2=v2",
    metavar='list[dict]'
)
@click.argument("alias_name")
@click.argument("description")
def create_key(
    cli_ctx,
    alias_name: str,
    description: str,
    administrators: list[str],
    users: list[str],
    tags: list[dict],
):
    """
    Create an Ethereum Private Key in AWS KmsAccount

    \b
    Args:
        alias_name str: The alias of the key you intend to create
        description str: The description of the key you intend to create.
    """
    if tags:
        tags_list = []
        for k_v in tags:
            k, v = k_v.split('=')
            tags_list.append(dict(k=v))
    key_spec = CreateKey(
        alias=alias_name,
        description=description,
        admins=administrators,
        users=users,
        tags=tags_list if tags else None,
    )
    key_id = kms_client.create_key(key_spec)
    cli_ctx.logger.success(f"Key created successfully with ID: {key_id}")


@kms.command(name="delete")
@ape_cli_context()
@click.argument("alias_name")
@click.option("-d", "--days", default=30, help="Number of days until key is deactivated")
def schedule_delete_key(cli_ctx, alias_name, days):
    if "alias" not in alias_name:
        alias_name = f"alias/{alias_name}"
    aws_accounts = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    kms_account = None
    for account in aws_accounts.accounts:
        if account.key_alias == alias_name:
            kms_account = account

    if not kms_account:
        cli_ctx.abort(f"No KMS Key with alias name: {alias_name}")

    delete_key_spec = DeleteKey(alias=alias_name, key_id=kms_account.key_id, days=days)
    key_alias = kms_client.delete_key(delete_key_spec)
    cli_ctx.logger.success(f"Key {key_alias} scheduled for deletion")
