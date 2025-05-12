import json
from functools import cached_property
from itertools import chain
from typing import TYPE_CHECKING, ClassVar

from ape.types import AddressType, HexBytes
from botocore.exceptions import BotoCoreError  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, SecretStr, field_validator

from ape_aws.exceptions import AwsAccessError
from ape_aws.session import Session

if TYPE_CHECKING:
    from botocore.client import BaseClient  # type: ignore[import-untyped]


class ImportKey(BaseModel):
    private_key: SecretStr

    @property
    def address(self):
        from eth_account import Account

        return Account.privateKeyToAccount(self.private_key.get_secret()).address

    @property
    def ec_private_key(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.derive_private_key(int(self.private_key, 16), ec.SECP256K1())

    @property
    def private_key_bin(self):
        """
        Returns the private key in binary format
        This is required for the `boto3.client.import_key_material` method
        """
        from cryptography.hazmat.primitives import serialization

        return self.ec_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key_der(self, import_token: bytes):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        return serialization.load_der_public_key(import_token, backend=default_backend())

    def encrypt(self, import_token: bytes):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        return self.public_key_der(import_token).encrypt(
            self.private_key_bin,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


class KmsKey(BaseModel):
    kms_client: ClassVar["BaseClient"]

    # NOTE: Using information from `aws kms list-aliases`
    id: str = Field(alias="TargetKeyId")
    arn: str = Field(alias="AliasArn")
    cached_alias: str | None = Field(default=None, alias="AliasName")
    cached_address: str | None = None

    @field_validator("cached_alias")
    def prune_alias_prepend(cls, value: str):
        return value.replace("alias/ape-aws/v1/", "")

    @property
    def metadata(self) -> dict:
        return self.kms_client.describe_key(KeyId=self.id)["KeyMetadata"]

    @property
    def enabled(self) -> bool:
        return self.metadata.get("Enabled", False)

    @property
    def alias(self) -> str:
        if self.cached_alias is not None:
            return self.cached_alias

        response = self.kms_client.list_aliases(KeyId=self.id)
        self.cached_alias = response["Aliases"][0]["AliasName"].replace("alias/ape-aws/v1/", "")
        assert isinstance(self.cached_alias, str)  # mypy
        return self.cached_alias

    @alias.setter  # type: ignore[attr-defined]
    def set_alias(self, alias: str):
        self.kms_client.update_alias(
            AliasName=f"alias/ape-aws/v1/{alias}",
            TargetKeyId=self.id,
            KeyUsage="SIGN_VERIFY",
        )
        self.cached_alias = alias

    @property
    def public_key(self) -> HexBytes:
        try:
            return HexBytes(self.kms_client.get_public_key(KeyId=self.id)["PublicKey"][-64:])
        except (self.kms_client.exceptions.KMSInvalidStateException, BotoCoreError) as e:
            # NOTE: Handle here since `.keys` is the main access point for the external API
            raise AwsAccessError(e) from e

    @property
    def address(self) -> AddressType:
        if self.cached_address:
            return self.cached_address

        from eth_utils import keccak, to_checksum_address

        return AddressType(to_checksum_address(keccak(self.public_key)[-20:]))

    def add_tags(self, tags: list[dict[str, str]]):
        self.kms_client.tag_resource(KeyId=self.id, Tags=tags)

    def get_policy(self) -> dict:
        response = self.kms_client.get_key_policy(KeyId=self.id)
        return json.loads(response["Policy"])

    @staticmethod
    def USER_KEY_POLICY(user_arn: str, key_arn: str) -> dict:
        return dict(
            Sid="Allow use of a specific key",
            Effect="Allow",
            Principal=dict(AWS=user_arn),
            Action=["kms:Sign", "kms:Verify", "kms:GetPublicKey"],
            Resource=key_arn,
        )

    def set_policy(
        self,
        users_to_add: list[str] | None = None,
        users_to_remove: list[str] | None = None,
    ):
        policy = self.get_policy()

        for user_arn in users_to_remove or []:
            policy["Statement"] = [
                stmt for stmt in policy["Statement"] if stmt["Principal"]["AWS"] != user_arn
            ]

        for user_arn in users_to_add or []:
            for stmt in policy["Statement"]:
                if stmt["Principal"]["AWS"] == user_arn:
                    break

            else:
                policy["Statement"].append(self.USER_KEY_POLICY(user_arn, self.arn))

        self.kms_client.put_key_policy(
            KeyId=self.id,
            PolicyName="default",
            Policy=json.dumps(policy),
        )

    def sign(self, msghash: bytes) -> bytes:
        response = self.kms_client.sign(
            KeyId=self.id,
            Message=msghash,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return response.get("Signature")

    def delete(self, days: int = 30):
        if self.alias:
            self.kms_client.delete_alias(AliasName=f"alias/ape-aws/v1/{self.alias}")

        self.kms_client.schedule_key_deletion(
            KeyId=self.id,
            PendingWindowInDays=days,
        )


class KmsClient(Session):
    @cached_property
    def kms_client(self):
        client = self.session.client("kms")
        KmsKey.kms_client = client  # DI
        return client

    @cached_property
    def keys(self) -> dict[str, KmsKey]:
        # NOTE: Uses aliases to get alias faster (no additional lookups needed)
        paginator = self.kms_client.get_paginator("list_aliases")
        pages = map(lambda data: data["Aliases"], paginator.paginate())

        try:
            # NOTE: Use `itertools.chain` since it is segmented into list of lists
            # NOTE: Just look for `alias/ape-aws/` alias in case we add v2, v3, etc.
            key_data = filter(lambda k: k["AliasName"].startswith("alias/ape-aws/"), chain(*pages))
        except BotoCoreError as e:
            # NOTE: Handle here since `.keys` is the main access point for the external API
            raise AwsAccessError(e) from e

        keys = map(KmsKey.model_validate, key_data)
        return {key.alias: key for key in keys}

    def generate_key(self, alias: str) -> KmsKey:
        response = self.kms_client.create_key(
            Description="Generated Key Created with Ape-AWS",
            KeyUsage="SIGN_VERIFY",
            KeySpec="ECC_SECG_P256K1",
            Origin="AWS_KMS",
        )

        key = KmsKey(
            TargetKeyId=response["KeyMetadata"]["KeyId"],
            AliasArn=response["KeyMetadata"]["Arn"],
        )

        self.kms_client.create_alias(
            TargetKeyId=key.id,
            AliasName=f"alias/ape-aws/v1/{alias}",
        )

        key.cached_alias = alias
        self.keys.update({alias: key})  # Update cache
        return key

    def import_key(self, alias: str, private_key: ImportKey) -> KmsKey:
        response = self.kms_client.create_key(
            Description="Imported Key Created with Ape-AWS",
            KeyUsage="SIGN_VERIFY",
            KeySpec="ECC_SECG_P256K1",
            Origin="IMPORTED",
        )

        key = KmsKey(
            TargetKeyId=response["KeyMetadata"]["KeyId"],
            AliasArn=response["KeyMetadata"]["Arn"],
        )

        import_token_bytes = bytes.fromhex(response["ImportToken"])
        self.kms_client.import_key_material(
            KeyId=key.id,
            ImportToken=response["ImportToken"],
            EncryptedKeyMaterial=private_key.encrypt(import_token_bytes),
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )

        self.kms_client.create_alias(
            TargetKeyId=key.id,
            AliasName=f"alias/ape-aws/v1/{alias}",
            KeyUsage="SIGN_VERIFY",
        )

        key.cached_alias = alias
        self.keys.update({key.id: key})  # Update cache
        return key

    def delete_key(self, key_id: str, days: int = 30):
        key = self.keys.pop(key_id)  # Remove from cache
        key.delete(days=days)
