from pydantic import BaseModel, Field

from typing import Any, Iterator, Optional

from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_pydantic_types import HexBytes
from eth_utils import keccak, to_checksum_address

from ape.api.accounts import AccountContainerAPI, AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, SignableMessage, TransactionSignature

from .utils import _convert_der_to_rsv
from .client import kms_client


class KeyBaseModel(BaseModel):
    alias: str = Field(required=True)


class CreateKeyModel(KeyBaseModel):
    description: str | None = Field(default=None, required=False)
    policy: str | None = Field(default=None, required=False)
    key_usage: str | None = Field(default='SIGN_VERIFY', required=False)
    key_spec: str | None = Field(default='ECC_SECG_P256K1', required=False)
    admins: list[str] | None = Field(required=False)
    users: list[str] | None = Field(required=False)
    tags: list[dict[str, str]] | None = Field(required=False)
    multi_region: bool | None = Field(default=False, required=False)
    ADMIN_KEY_POLICY: str | None = """{
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
    USER_KEY_POLICY: str | None = """{
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
    days: int | None = Field(default=30, required=False)

    @property
    def kms_account(self):
        if "alias" not in self.alias:
            alias_name = f"alias/{self.alias}"
        aws_accounts = AwsAccountContainer(data_folder='./', account_type=KmsAccount)
        kms_account = None
        for account in aws_accounts.accounts:
            if account.key_alias == alias_name:
                kms_account = account

        return kms_account

    @property
    def key_id(self):
        return self.kms_account.key_id


class AwsAccountContainer(AccountContainerAPI):

    @property
    def aliases(self) -> Iterator[str]:
        return map(lambda x: x.alias, kms_client.raw_aliases)

    def __len__(self) -> int:
        return len(kms_client.raw_aliases)

    @property
    def accounts(self) -> Iterator[AccountAPI]:
        return map(
            lambda x: KmsAccount(
                key_alias=x.alias,
                key_id=x.key_id,
                key_arn=x.arn,
            ),
            kms_client.raw_aliases
        )


class KmsAccount(AccountAPI):
    key_alias: str
    key_id: str
    key_arn: str

    @property
    def public_key(self):
        return kms_client.get_public_key(self.key_id)

    @property
    def address(self) -> AddressType:
        return to_checksum_address(
            keccak(self.public_key[-64:])[-20:].hex().lower()
        )

    def _sign_raw_hash(self, msghash: HexBytes) -> Optional[bytes]:
        return kms_client.sign(self.key_id, msghash)

    def sign_raw_msghash(self, msghash: HexBytes) -> Optional[MessageSignature]:
        if len(msghash) != 32:
            return None

        if signature := self._sign_raw_hash(msghash):
            return MessageSignature(**_convert_der_to_rsv(signature, signature[0] + 27))

        return None

    def sign_message(
        self, msg: Any, **signer_options
    ) -> Optional[MessageSignature]:
        if isinstance(msg, SignableMessage):
            message = msg
        if isinstance(msg, str):
            if msg.startswith('0x'):
                message = encode_defunct(hexstr=msg)
            else:
                message = encode_defunct(text=msg)
        if isinstance(msg, bytes):
            message = encode_defunct(primitive=msg)
        msg_sig = self.sign_raw_msghash(_hash_eip191_message(message))
        # TODO: Figure out how to properly compute v
        if not self.check_signature(msg, msg_sig):
            msg_sig = MessageSignature(v=msg_sig.v + 1, r=msg_sig.r, s=msg_sig.s)

        return msg_sig

    def sign_transaction(
        self, txn: TransactionAPI, **signer_options
    ) -> Optional[TransactionAPI]:
        """
        Sign an EIP-155 transaction.

        Args:
            txn (``TransactionAPI``): A pydantic model of transaction data.

        Returns:
            TransactionAPI | None
        """
        unsigned_txn = serializable_unsigned_transaction_from_dict(
            dict(
                nonce=txn.nonce,
                gasPrice=txn.max_priority_fee,
                gas=txn.max_fee,
                to=txn.receiver,
                value=txn.value,
                data=txn.data
            )
        ).hash()
        msg_sig = self._sign_raw_hash(unsigned_txn)
        txn.signature = TransactionSignature(
            **_convert_der_to_rsv(msg_sig, (2 * txn.chain_id + 35) if txn.chain_id else 27)
        )
        # TODO: Figure out how to properly compute v
        if not self.check_signature(txn):
            txn.signature = TransactionSignature(
                v=txn.signature.v + 1,
                r=txn.signature.r,
                s=txn.signature.s,
            )

        return txn
