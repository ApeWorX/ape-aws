import click
from pathlib import Path

from eth_account import Account as EthAccount
from eth_account.hdaccount import ETHEREUM_DEFAULT_PATH

from ape.cli import ape_cli_context

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
@click.option(
    "-d",
    "--description",
    "description",
    help="The description of the key you intend to create.",
)
@click.argument("alias_name")
def create_key(
    cli_ctx,
    alias_name: str,
    administrators: list[str],
    users: list[str],
    description: str,
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
    help="The private key you intend to import",
    metavar="str",
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
@click.option(
    "--use-mnemonic",
    "import_from_mnemonic",
    help="Import a key from a mnemonic phrase",
    is_flag=True,
)
@click.option(
    "--hd-path",
    "hd_path",
    help="The hierarchical deterministic path to derive the key from",
    metavar="str",
)
@click.argument("alias_name")
def import_key(
    cli_ctx,
    alias_name: str,
    private_key: bytes | str | Path,
    administrators: list[str],
    users: list[str],
    description: str,
    import_from_mnemonic: bool,
    hd_path: str,
):
    if private_key:
        path = Path(private_key)
        if path.exists() and path.is_file():
            cli_ctx.logger.info(f"Reading private key from {path}")
            private_key = path.read_text().strip()

    if import_from_mnemonic:
        if not hd_path:
            hd_path = ETHEREUM_DEFAULT_PATH
        mnemonic = click.prompt("Enter your mnemonic phrase", hide_input=True)
        EthAccount.enable_unaudited_hdwallet_features()
        account = EthAccount.from_mnemonic(mnemonic, account_path=hd_path)
        private_key = account.key.hex()

    key_spec = ImportKeyRequest(
        alias=alias_name,
        description=description,  # type: ignore
        admins=administrators,
        users=users,
    )
    key_id = kms_client.create_key(key_spec)
    create_key_response = kms_client.get_parameters(key_id)
    public_key = create_key_response["PublicKey"]
    import_token = create_key_response["ImportToken"]
    import_key_spec = ImportKey(
        **key_spec.model_dump(),
        key_id=key_id,  # type: ignore
        public_key=public_key,  # type: ignore
        private_key=private_key,  # type: ignore
        import_token=import_token,  # type: ignore
    )
    response = kms_client.import_key(import_key_spec)
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        cli_ctx.abort("Key failed to import into KMS")
    cli_ctx.logger.success(f"Key imported successfully with ID: {key_id}")


# TODO: Add `ape aws kms sign-message [message]`
# TODO: Add `ape aws kms verify-message [message] [hex-signature]`


@kms.command(name="delete")
@ape_cli_context()
@click.argument("alias_name")
@click.option("-d", "--days", default=30, help="Number of days until key is deactivated")
def schedule_delete_key(cli_ctx, alias_name, days):
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
    cli_ctx.logger.success(f"Key {key_alias} scheduled for deletion in {days} days")
