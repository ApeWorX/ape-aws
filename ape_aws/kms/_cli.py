import boto3
import click

from ape.cli import ape_cli_context

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
@ape_cli_context
@click.argument("alias")
def account(alias):
    """
    Import an existing Ethereum Private Key into AWS KMS
    """
    aws_accounts = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    kms_account = None
    for account in list(aws_accounts.accounts):
        if account.key_alias == alias:
            kms_account = account

    if not kms_account:
        raise ValueError(f"No KMS Key with alias name {alias}")

    return kms_account


@kms.command()
@ape_cli_context
@click.argument("alias_name")
@click.argument("description")
@click.argument("tag_key")
@click.argument("tag_value")
@click.option("-a", "--admin", "administrators", multiple=True, nargs="+")
@click.option("-u", "--user", "users", multiple=True, nargs="+")
def import_key(alias_name, description, tag_key, tag_value, administrators, users):
    """
    Import an existing Ethereum Private Key into AWS KMS
    """
    aws_account = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    response = aws_account.kms_client.create_key(
        Description=description,
        KeyUsage='SIGN_VERIFY',
        KeySpec='ECC_SECG_P256K1',
        Origin='External',
        MultiRegion=False,
    )
    key_id = response['KeyMetadata']['KeyId']
    aws_account.kms_client.create_alias(
        AliasName=f'alias/{alias_name}',
        TargetKeyId=key_id,
    )
    aws_account.kms_client.tag_resource(
        KeyId=key_id,
        Tags=[{'TagKey': tag_key, 'TagValue': tag_value}],
    )
    # Note: Get the ARN from AWS
    for arn in administrators:
        aws_account.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=ADMIN_KEY_POLICY.format(arn=arn)
        )
    # Note: get ARN from AWS
    for arn in users:
        aws_account.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=USER_KEY_POLICY.format(arn=arn)
        )

    click.echo(f"Key created successfully with ID: {key_id}")


@kms.command()
@ape_cli_context
@click.argument("alias_name")
@click.option("--days", help="Number of days until key is deactivated")
def schedule_delete_key(alias_name, days=30):
    aws_accounts = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    kms_account = None
    for account in list(aws_accounts.accounts):
        if account.key_alias == alias_name:
            kms_account = account

    if not kms_account:
        raise ValueError(f"No KMS Key with alias name {alias_name}")

    kms_account.kms_client.schedule_delete_key(
        KeyId=kms_account.key_id, PendingWindowInDays=days
    )
    return kms_account
