from datetime import datetime
from typing import ClassVar

import boto3  # type: ignore[import]
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from eth_account import Account
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="TargetKeyId")
    creation: datetime = Field(alias="CreationDate")
    last_updated: datetime = Field(alias="LastUpdatedDate")


class KeyBaseModel(BaseModel):
    alias: str
    model_config = ConfigDict(populate_by_name=True)


class CreateKeyModel(KeyBaseModel):
    description: str | None = Field(default=None, alias="Description")
    policy: str | None = Field(default=None, alias="Policy")
    key_usage: str = Field(default="SIGN_VERIFY", alias="KeyUsage")
    key_spec: str = Field(default="ECC_SECG_P256K1", alias="KeySpec")
    admins: list[str] = []
    users: list[str] = []
    tags: list[dict[str, str]] | None = Field(default=None, alias="Tags")
    multi_region: bool | None = Field(default=None, alias="MultiRegion")
    origin: str = Field(alias="Origin")
    ADMIN_KEY_POLICY: ClassVar[
        str
    ] = """{
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
    USER_KEY_POLICY: ClassVar[
        str
    ] = """{
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

    def to_aws_dict(self):
        alias_dict = {}
        for k, v in self.model_dump().items():
            field = self.model_fields[k]
            if field.alias and v:
                alias_dict[field.alias] = v
        return alias_dict


class CreateKey(CreateKeyModel):
    origin: str = Field(default="AWS_KMS", alias="Origin")


class ImportKeyRequest(CreateKeyModel):
    origin: str = Field(default="EXTERNAL", alias="Origin")


class ImportKey(ImportKeyRequest):
    key_id: str = Field(default=None, alias="KeyId")
    public_key: bytes = Field(default=None, alias="PublicKey")
    private_key: str | bytes = Field(default=None, alias="PrivateKey")
    import_token: bytes = Field(default=None, alias="ImportToken")

    @field_validator("private_key")
    def validate_private_key(cls, value):
        if value.startswith("0x"):
            value = value[2:]
        return value

    @property
    def get_account(self):
        return Account.privateKeyToAccount(self.private_key)

    @property
    def ec_private_key(self):
        loaded_key = self.private_key
        if isinstance(loaded_key, bytes):
            loaded_key = ec.derive_private_key(int(self.private_key, 16), ec.SECP256K1())
        elif isinstance(loaded_key, str):
            loaded_key = bytes.fromhex(loaded_key[2:])
            loaded_key = ec.derive_private_key(int(self.private_key, 16), ec.SECP256K1())
        return loaded_key

    @property
    def private_key_hex(self):
        if isinstance(self.private_key, str):
            return self.private_key
        elif isinstance(self.private_key, bytes):
            return self.private_key.hex()
        return self.private_key.private_numbers().private_value.to_bytes(32, "big").hex()

    @property
    def private_key_bin(self):
        """
        Returns the private key in binary format
        This is required for the `boto3.client.import_key_material` method
        """
        return self.ec_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def private_key_pem(self):
        """
        Returns the private key in PEM format for use in outside applications.
        """
        return self.ec_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key_der(self):
        return serialization.load_der_public_key(
            self.public_key,
            backend=default_backend(),
        )

    @property
    def encrypted_private_key(self):
        if not self.public_key:
            raise ValueError("Public key not found")

        return self.public_key_der.encrypt(
            self.private_key_bin,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


class DeleteKey(KeyBaseModel):
    key_id: str
    days: int = 30


class KmsClient:
    def __init__(self):
        self.client = boto3.client("kms")

    @property
    def raw_aliases(self) -> list[AliasResponse]:
        paginator = self.client.get_paginator("list_aliases")
        pages = paginator.paginate()
        return [
            AliasResponse(**page)
            for alias_data in pages
            for page in alias_data["Aliases"]
            if "alias/aws/" not in page["AliasName"]
        ]

    def get_public_key(self, key_id: str):
        return self.client.get_public_key(KeyId=key_id)["PublicKey"]

    def sign(self, key_id, msghash):
        response = self.client.sign(
            KeyId=key_id,
            Message=msghash,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return response.get("Signature")

    def create_key(self, key_spec: CreateKey | ImportKeyRequest):
        response = self.client.create_key(**key_spec.to_aws_dict())

        key_id = response["KeyMetadata"]["KeyId"]
        self.client.create_alias(
            AliasName=f"alias/{key_spec.alias}",
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
                    PolicyName="default",
                    Policy=key_spec.ADMIN_KEY_POLICY.format(arn=arn),
                )
        if key_spec.users:
            for arn in key_spec.users:
                kms_client.client.put_key_policy(
                    KeyId=key_id,
                    PolicyName="default",
                    Policy=key_spec.USER_KEY_POLICY.format(arn=arn),
                )
        return key_id

    def import_key(self, key_spec: ImportKey):
        return self.client.import_key_material(
            KeyId=key_spec.key_id,
            ImportToken=key_spec.import_token,
            EncryptedKeyMaterial=key_spec.encrypted_private_key,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )

    def get_parameters(self, key_id: str):
        return self.client.get_parameters_for_import(
            KeyId=key_id,
            WrappingAlgorithm="RSAES_OAEP_SHA_256",
            WrappingKeySpec="RSA_2048",
        )

    def delete_key(self, key_spec: DeleteKey):
        self.client.delete_alias(AliasName=key_spec.alias)
        self.client.schedule_key_deletion(KeyId=key_spec.key_id, PendingWindowInDays=key_spec.days)
        return key_spec.alias


class IamClient:
    def __init__(self):
        self.client = boto3.client("iam")

    def list_users(self):
        result = self.client.list_users()
        return result.get("Users")

    def list_admins(self):
        admins = []
        for user in self.list_users():
            user_name = user["UserName"]
            user_policies = self.client.list_attached_user_policies(UserName=user_name)
            for policy in user_policies["AttachedPolicies"]:
                if policy["PolicyName"] == "AdministratorAccess":
                    admins.append(user_name)
        return admins


kms_client = KmsClient()
iam_client = IamClient()
