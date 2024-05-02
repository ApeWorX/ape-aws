import boto3

from datetime import datetime
from pydantic import BaseModel, Field


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="TargetKeyId")
    creation: datetime = Field(alias="CreationDate")
    last_updated: datetime = Field(alias="LastUpdatedDate")


class KeyBaseModel(BaseModel):
    alias: str


class CreateKeyModel(KeyBaseModel):
    description: str | None = Field(default=None, required=False)
    policy: str | None = Field(default=None, required=False)
    key_usage: str = 'SIGN_VERIFY'
    key_spec: str = 'ECC_SECG_P256K1'
    admins: list[str] | None = Field(required=False)
    users: list[str] | None = Field(required=False)
    tags: list[dict[str, str]] | None = Field(required=False)
    multi_region: bool | None = Field(default=False, required=False)
    ADMIN_KEY_POLICY: str = """{
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
    USER_KEY_POLICY: str = """{
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


class CreateKey(CreateKeyModel):
    origin: str = 'AWS_KMS'


class ImportKey(CreateKeyModel):
    origin: str = 'EXTERNAL'


class DeleteKey(KeyBaseModel):
    key_id: str
    days: int = 30


class Client:

    def __init__(self, client_name: str):
        self.client_name = client_name
        self.client = boto3.client(self.client_name)


class KmsClient(Client):

    def __init__(self):
        super().__init__(client_name='kms')

    @property
    def raw_aliases(self) -> list[AliasResponse]:
        paginator = self.client.get_paginator('list_aliases')
        pages = paginator.paginate()
        return [
            AliasResponse(**page)
            for alias_data in pages
            for page in alias_data['Aliases']
            if "alias/aws" not in page["AliasName"]
        ]

    def get_public_key(self, key_id: str):
        return self.client.get_public_key(KeyId=key_id)["PublicKey"]

    def sign(self, key_id, msghash):
        response = self.client.sign(
            KeyId=key_id,
            Message=msghash,
            MessageType='DIGEST',
            SigningAlgorithm='ECDSA_SHA_256',
        )
        return response.get('Signature')

    def create_key(self, key_spec: CreateKey):
        response = self.client.create_key(
            Description=key_spec.description,
            KeyUsage=key_spec.key_usage,
            KeySpec=key_spec.key_spec,
            Origin=key_spec.origin,
            MultiRegion=key_spec.multi_region,
        )
        key_id = response['KeyMetadata']['KeyId']
        self.client.create_alias(
            AliasName=f'alias/{key_spec.alias}',
            TargetKeyId=key_id,
        )
        if key_spec.tags:
            self.client.tag_resource(
                KeyId=key_id,
                Tags=key_spec.tags,
            )
        if key_spec.admins:
            for arn in key_spec.admins:
                self.client.put_key_policy(
                    KeyId=key_id,
                    PolicyName='default',
                    Policy=key_spec.ADMIN_KEY_POLICY.format(arn=arn)
                )
        if key_spec.users:
            for arn in key_spec.users:
                kms_client.client.put_key_policy(
                    KeyId=key_id,
                    PolicyName='default',
                    Policy=key_spec.USER_KEY_POLICY.format(arn=arn)
                )
        return key_id

    def delete_key(self, key_spec: DeleteKey):
        self.client.delete_alias(AliasName=key_spec.alias)
        self.client.schedule_key_deletion(
            KeyId=key_spec.key_id, PendingWindowInDays=key_spec.days
        )
        return key_spec.alias


class IamClient(Client):

    def __init__(self):
        super().__init__(client_name='iam')

    def list_users(self):
        result = self.client.list_users()
        return result.get('Users')

    def list_admins(self):
        admins = []
        for user in self.list_users():
            user_name = user['UserName']
            user_policies = self.client.list_attached_user_policies(UserName=user_name)
            for policy in user_policies['AttachedPolicies']:
                if policy['PolicyName'] == 'AdministratorAccess':
                    admins.append(user_name)
        return admins


kms_client = KmsClient()
iam_client = IamClient()
