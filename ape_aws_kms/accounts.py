import boto3
import ecdsa

from datetime import datetime
from typing import Any, Iterator, List, Optional

from eth_account.messages import (
    _hash_eip191_message,
    encode_defunct,
)
from eth_pydantic_types import HexBytes
from eth_utils import keccak, to_checksum_address
from pydantic import BaseModel, Field

from ape.api.accounts import AccountContainerAPI, AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature
from ape.utils import cached_property


SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="TargetKeyId")
    creation: datetime = Field(alias="CreationDate")
    last_updated: datetime = Field(alias="LastUpdatedDate")


class AwsAccountContainer(AccountContainerAPI):
    @cached_property
    def kms_client(self):
        return boto3.client('kms')

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
        return boto3.client('kms')

    @cached_property
    def public_key(self):
        return self.kms_client.get_public_key(KeyId=self.key_id)["PublicKey"]

    @cached_property
    def address(self) -> AddressType:
        return to_checksum_address(
            keccak(self.public_key[-64:])[-20:].hex().lower()
        )

    def sign_raw_msghash(self, msghash: HexBytes) -> Optional[MessageSignature]:
        """
        follow: https://github.com/ApeWorX/ape/pull/1966/files#diff-c308960cdf9376a4c05b2bb028a5a79e22c8a12b4c99633580062ec04ab613e2R60

        AccountAPI has check_message to do a round trip check to make sure sig is correct and
        that the address is returning what we want
        """
        response = self.kms_client.sign(
            KeyId=self.key_id,
            Message=msghash,
            MessageType='DIGEST',
            SigningAlgorithm='ECDSA_SHA_256',
        )
        return response['Signature']

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        signable_message = encode_defunct(text=msg)
        signature = self.sign_raw_msghash(_hash_eip191_message(signable_message))
        r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
        if s > SECP256_K1_N / 2:
            s = SECP256_K1_N - s
        r = r.to_bytes(32, byteorder='big')
        s = s.to_bytes(32, byteorder='big')
        v = signature[0] + 27
        if self.check_signature(
            signable_message,
            message_signature := MessageSignature.from_vrs(bytes([v]) + r + s),
        ):
            return message_signature
        elif self.check_signature(
            signable_message,
            message_signature := MessageSignature.from_vrs(bytes([v + 1]) + r + s),
        ):
            return message_signature
        else:
            raise ValueError("Signature failed to verify")

    def sign_transaction(self, txn: TransactionAPI, **signer_options) -> Optional[TransactionAPI]:
        """
        To be implemented
        EIP-191 -> Describing a text based message to sign

        EIP-712 -> Subclass of EIP-191 messages. First byte is a specific value
        implemented in the EIP712 Package

        Break EIP-712 down further into a raw hash

        Through EthAccount?
        """
