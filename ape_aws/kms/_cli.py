import click
from ape.cli import ape_cli_context

from ape_aws.accounts import AwsAccountContainer, KmsAccount
from ape_aws.client import CreateKey, DeleteKey, ImportKey, ImportKeyRequest, kms_client


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
    help="Apply key policy to a list of administrators if applicable, ex. -a ARN1, -a ARN2",
    metavar="list[ARN]",
)
@click.option(
    "-u",
    "--user",
    "users",
    multiple=True,
    help="Apply key policy to a list of users if applicable, ex. -u ARN1, -u ARN2",
    metavar="list[ARN]",
)
@click.argument("alias_name")
@click.argument("description")
def create_key(
    cli_ctx,
    alias_name: str,
    description: str,
    administrators: list[str],
    users: list[str],
):
    """
    Create an Ethereum Private Key in AWS KmsAccount

    \b
    Args:
        alias_name str: The alias of the key you intend to create
        description str: The description of the key you intend to create.
    """
    key_spec = CreateKey(
        alias=alias_name,
        Description=description,
        admins=administrators,
        users=users,
    )
    key_id = kms_client.create_key(key_spec)
    cli_ctx.logger.success(f"Key created successfully with ID: {key_id}")


@kms.command(name="import")
@ape_cli_context()
@click.option(
    "-p",
    "--private-key",
    "private_key",
    multiple=False,
    help="The private key to import",
)
@click.option(
    "-a",
    "--admin",
    "administrators",
    multiple=True,
    help="Apply key policy to a list of administrators if applicable, ex. -a ARN1, -a ARN2",
    metavar="list[ARN]",
)
@click.option(
    "-u",
    "--user",
    "users",
    multiple=True,
    help="Apply key policy to a list of users if applicable, ex. -u ARN1, -u ARN2",
    metavar="list[ARN]",
)
@click.option(
    "-d",
    "--description",
    "description",
    help="The description of the key you intend to create.",
    metavar="str",
)
@click.argument("alias_name")
def import_key(
    cli_ctx,
    alias_name: str,
    private_key: bytes,
    administrators: list[str],
    users: list[str],
    description: str,
):
    def ask_for_passphrase():
        return click.prompt(
            "Create Passphrase to encrypt account",
            hide_input=True,
            confirmation_prompt=True,
        )

    passphrase = ask_for_passphrase()
    key_spec = ImportKeyRequest(
        alias=alias_name,
        description=description,
        admins=administrators,
        users=users,
    )
    key_id = kms_client.create_key(key_spec)
    create_key_response = kms_client.get_parameters(key_id)
    public_key = create_key_response["PublicKey"]
    import_token = create_key_response["ImportToken"]
    import_key_spec = ImportKey(
        **key_spec.model_dump(),
        key_id=key_id,
        public_key=public_key,
        private_key=private_key,
        import_token=import_token,
    )
    response = kms_client.import_key(import_key_spec)
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        cli_ctx.abort("Key failed to import into KMS")
    cli_ctx.logger.success(f"Key imported successfully with ID: {key_id}")
    aws_account_container = AwsAccountContainer(name="aws", account_type=KmsAccount)
    aws_account_container.add_private_key(alias_name, passphrase, import_key_spec.private_key_hex)


# TODO: Add `ape aws kms sign-message [message]`
# TODO: Add `ape aws kms verify-message [message] [hex-signature]`


@kms.command(name="delete")
@ape_cli_context()
@click.argument("alias_name")
@click.option("-p", "--purge", is_flag=True, help="Purge the key from the system")
@click.option("-d", "--days", default=30, help="Number of days until key is deactivated")
def schedule_delete_key(cli_ctx, alias_name, purge, days):
    if "alias" not in alias_name:
        alias_name = f"alias/{alias_name}"
    kms_account = None
    for account in kms_client.raw_aliases:
        if account.alias == alias_name:
            kms_account = account

    if not kms_account:
        cli_ctx.abort(f"No KMS Key with alias name: {alias_name}")

    delete_key_spec = DeleteKey(alias=alias_name, key_id=kms_account.key_id, days=days)
    key_alias = kms_client.delete_key(delete_key_spec)
    if purge:
        aws_account_container = AwsAccountContainer(name="aws", account_type=KmsAccount)
        aws_account_container.delete_account(key_alias)
    cli_ctx.logger.success(f"Key {key_alias} scheduled for deletion in {days} days")
