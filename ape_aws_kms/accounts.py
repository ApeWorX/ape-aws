import boto3
import json

from datetime import datetime
from hashlib import sha256
from typing import Any, Iterator, List, Optional

from eth_account import Account
from eth_account.messages import _hash_eip191_message, SignableMessage
from eth_pydantic_types import HexBytes
from eth_utils import keccak, to_checksum_address
from pydantic import BaseModel, Field

from ape.api.accounts import AccountContainerAPI, AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature
from ape.utils import cached_property


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
                alias=x.alias,
                key_id=x.key_id,
                key_arn=x.arn,
            ),
            self.raw_aliases
        )


class KmsAccount(AccountAPI):
    alias: str
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
        return to_checksum_address(keccak(self.public_key)[:20])

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
        return response

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        message = None
        if isinstance(msg, str):
            message = sha256(msg.encode()).digest()
        elif isinstance(msg, dict):
            message = sha256(json.dumps(msg).encode('utf-8')).digest()
        elif isinstance(msg, bytes):
            message = sha256(msg).digest()
        elif isinstance(msg, int):
            message = sha256(
                msg.to_bytes((msg.bit_length() + 7) // 8, byteorder='big')
            ).digest()
        if message:
            signable_message = SignableMessage(
                version=(0x00).to_bytes(1, byteorder='big'),
                header=self.address.encode('utf-8'),
                body=message,
            )
            eip_message = _hash_eip191_message(signable_message)
            response = self.sign_raw_msghash(eip_message)
            signature = response['Signature']
            r = signature[-64:-32]
            s = signature[-32:]
            for v in [27, 28]:
                # WORK IN PROGRESS HERE
                vrs = int(v).to_bytes(1, 'big') + r + s
                message_signature = MessageSignature.from_vrs(vrs)
                breakpoint()
                try:
                    if self.check_signature(msg, message_signature):
                        return response
                except:
                    continue

            raise ValueError("Signature failed to verify")
        raise ValueError("Invalid message type")

    def sign_transaction(self, txn: TransactionAPI, **signer_options) -> Optional[TransactionAPI]:
        """
        To be implemented
        EIP-191 -> Describing a text based message to sign

        EIP-712 -> Subclass of EIP-191 messages. First byte is a specific value
        implemented in the EIP712 Package

        Break EIP-712 down further into a raw hash

        Through EthAccount?
        """
