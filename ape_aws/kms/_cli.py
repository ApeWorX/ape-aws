import boto3
import click

from ape.cli import ape_cli_context

from ape_aws.accounts import KmsAccount, AwsAccountContainer


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
@click.argument("administrators")
@click.argument("users")
def import_key(alias_name, description, tag_key, tag_value, administrators, users):
    """
    Import an existing Ethereum Private Key into AWS KMS
    """
    aws_account = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
    response = aws_account.kms_client.create_key(
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
            Policy='''{
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [{
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": "%s"},
                    "Action": "kms:*",
                    "Resource": "*"
                }]
            }''' % arn
        )
    # Note: get ARN from AWS
    for arn in users:
        aws_account.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy='''{
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [{
                    "Sid": "Allow use of the key",
                    "Effect": "Allow",
                    "Principal": {"AWS": "%s"},
                    "Action": ["kms:Sign", "kms:Verify"],
                    "Resource": "*"
                }]
            }''' % arn
        )

    print("Key created successfully with ID: ", key_id)
