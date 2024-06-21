from functools import cached_property
from typing import Any, Iterator, Optional

from ape.api.accounts import AccountAPI, AccountContainerAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, SignableMessage, TransactionSignature
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_pydantic_types import HexBytes
from eth_typing import Hash32
from eth_utils import keccak, to_checksum_address

from .client import kms_client
from .utils import _convert_der_to_rsv


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
            kms_client.raw_aliases,
        )


class KmsAccount(AccountAPI):
    key_alias: str
    key_id: str
    key_arn: str

    @property
    def alias(self) -> str:
        return self.key_alias.replace("alias/", "")

    @property
    def public_key(self):
        return kms_client.get_public_key(self.key_id)

    @cached_property
    def address(self) -> AddressType:
        return to_checksum_address(keccak(self.public_key[-64:])[-20:].hex().lower())

    def _sign_raw_hash(self, msghash: HexBytes | Hash32) -> Optional[bytes]:
        return kms_client.sign(self.key_id, msghash)

    def sign_raw_msghash(self, msghash: HexBytes | Hash32) -> Optional[MessageSignature]:
        if len(msghash) != 32:
            return None

        if not (signature := self._sign_raw_hash(msghash)):
            return None

        msg_sig = MessageSignature(**_convert_der_to_rsv(signature, 27))
        # TODO: Figure out how to properly compute v
        if not self.check_signature(msghash, msg_sig):
            msg_sig = MessageSignature(v=msg_sig.v + 1, r=msg_sig.r, s=msg_sig.s)

        return msg_sig

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        if isinstance(msg, SignableMessage):
            message = msg
        if isinstance(msg, str):
            if msg.startswith("0x"):
                message = encode_defunct(hexstr=msg)
            else:
                message = encode_defunct(text=msg)
        if isinstance(msg, bytes):
            message = encode_defunct(primitive=msg)
        return self.sign_raw_msghash(_hash_eip191_message(message))

    def sign_transaction(self, txn: TransactionAPI, **signer_options) -> Optional[TransactionAPI]:
        """
        Sign an EIP-155 transaction.
        CHECK TYPE 0 transactions.

        Args:
            txn (``TransactionAPI``): A pydantic model of transaction data.

        Returns:
            TransactionAPI | None
        """
        unsigned_txn = serializable_unsigned_transaction_from_dict(txn.model_dump()).hash()
        if not (msg_sig := self._sign_raw_hash(unsigned_txn)):
            return None
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
