import click

from ape_aws.accounts import KmsAccount, AwsAccountContainer


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


@kms.command()
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
    aws_account = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    response = aws_account.kms_client.create_key(
        Description=description,
        KeyUsage='SIGN_VERIFY',
        KeySpec='ECC_SECG_P256K1',
        Origin='AWS_KMS',
        MultiRegion=False,
    )
    key_id = response['KeyMetadata']['KeyId']
    aws_account.kms_client.create_alias(
        AliasName=f'alias/{alias_name}',
        TargetKeyId=key_id,
    )
    if tags:
        tags_list = []
        for k_v in tags:
            k, v = k_v.split('=')
            tags_list.append(dict(k=v))
        aws_account.kms_client.tag_resource(
            KeyId=key_id,
            Tags=tags_list,
        )
    for arn in administrators:
        aws_account.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=ADMIN_KEY_POLICY.format(arn=arn)
        )
    for arn in users:
        aws_account.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=USER_KEY_POLICY.format(arn=arn)
        )

    click.echo(f"Key created successfully with ID: {key_id}")


@kms.command()
@click.argument("alias_name")
@click.option("-d", "--days", default=30, help="Number of days until key is deactivated")
def schedule_delete_key(alias_name, days):
    if "alias" not in alias_name:
        alias_name = f"alias/{alias_name}"
    aws_accounts = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    kms_account = None
    for account in aws_accounts.accounts:
        if account.key_alias == alias_name:
            kms_account = account

    if not kms_account:
        raise ValueError(f"No KMS Key with alias name {alias_name}")

    kms_account.kms_client.delete_alias(AliasName=alias_name)
    kms_account.kms_client.schedule_key_deletion(
        KeyId=kms_account.key_id, PendingWindowInDays=days
    )
    click.echo(f"Key {kms_account.key_alias} scheduled for deletion")
