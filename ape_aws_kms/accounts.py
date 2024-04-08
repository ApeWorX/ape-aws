import boto3
import json

from datetime import datetime
from typing import Optional, Iterator, List

from eth_utils import keccak, to_checksum_address
from pydantic import BaseModel, Field

from ape.api import AccountContainerAPI, AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, TransactionSignature
from ape.utils import cached_property


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="KeyId")
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
            AliasResponse(**alias_data) for page in pages for alias_data in page
        ]

    @property
    def alias(self) -> Iterator[str]:
        # Get the alias attribute from each self.raw_aliases 
        return map(self.raw_aliases.alias)

    def __len__(self) -> int:
        return len(self.kms_clinet.list_aliases())

    @property
    def accounts(self) -> Iterator[AccountAPI]:
        # Get the values required, return KmsAccount for each self.raw_alias
        ... # self.kms_client.list_aliases -> KmsAccount


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

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        ... # self.kms_client.sign(<convert message to proper schema>) And convert to a message signature

    def sign_transaction(self, txn: TransactionAPI, **signer_options) -> Optional[TransactionAPI]:
        ... # self.kms_client.sign(<convert txn to proper schema>) Gets appended to the message


"""
EIP 191 and EIP 712

convert EIP 191 and EIP 712 messages in a utils module

ethereim-kms-signer example

get_sig_r_s_v()
"""
