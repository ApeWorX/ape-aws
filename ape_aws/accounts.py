from typing import Any

import boto3

from typing import Iterator, List, Optional

from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_pydantic_types import HexBytes
from eth_utils import keccak, to_checksum_address

from ape.api.accounts import AccountContainerAPI, AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, SignableMessage, TransactionSignature
from ape.utils import cached_property

from .utils import AliasResponse, _convert_der_to_rsv
from .client import client


class AwsAccountContainer(AccountContainerAPI):
    @cached_property
    def kms_client(self):
        return client.kms_client

    @cached_property
    def raw_aliases(self) -> List[AliasResponse]:
        paginator = self.kms_client.get_paginator('list_aliases')
        pages = paginator.paginate()
        return [
            AliasResponse(**page)
            for alias_data in pages
            for page in alias_data['Aliases']
            if "alias/aws" not in page["AliasName"]
        ]

    @property
    def aliases(self) -> Iterator[str]:
        return map(lambda x: x.alias, self.raw_aliases)

    def __len__(self) -> int:
        return len(self.raw_aliases)

    @property
    def accounts(self) -> Iterator[AccountAPI]:
        return map(
            lambda x: KmsAccount(
                key_alias=x.alias,
                key_id=x.key_id,
                key_arn=x.arn,
            ),
            self.raw_aliases
        )


class KmsAccount(AccountAPI):
    key_alias: str
    key_id: str
    key_arn: str

    @cached_property
    def kms_client(self):
        return client.kms_client

    @cached_property
    def public_key(self):
        return self.kms_client.get_public_key(KeyId=self.key_id)["PublicKey"]

    @cached_property
    def address(self) -> AddressType:
        return to_checksum_address(
            keccak(self.public_key[-64:])[-20:].hex().lower()
        )

    def _sign_raw_hash(self, msghash: HexBytes) -> Optional[bytes]:
        response = self.kms_client.sign(
            KeyId=self.key_id,
            Message=msghash,
            MessageType='DIGEST',
            SigningAlgorithm='ECDSA_SHA_256',
        )
        return response.get('Signature')

    def sign_raw_msghash(self, msghash: HexBytes) -> Optional[MessageSignature]:
        if len(msghash) != 32:
            return None

        if signature := self._sign_raw_hash(msghash):
            return MessageSignature(**_convert_der_to_rsv(signature, 27))

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
        if self.check_signature(msg, msg_sig):
            return msg_sig
        else:
            return MessageSignature(v=msg_sig.v + 1, r=msg_sig.r, s=msg_sig.s)

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
        return txn
