import boto3
import json

from datetime import datetime
from typing import Any, Iterator, List, Optional

from eth_utils import keccak, to_checksum_address
from pydantic import BaseModel, Field

from ape.api.accounts import AccountContainerAPI, AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, TransactionSignature
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
        # return [AliasResponse(**page) for page in pages for alias_data['Aliases'] in page]
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

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        ... # self.kms_client.sign(<convert message to proper schema>) And convert to a message signature

    def sign_transaction(self, txn: TransactionAPI, **signer_options) -> Optional[TransactionAPI]:
        ... # self.kms_client.sign(<convert txn to proper schema>) Gets appended to the message
