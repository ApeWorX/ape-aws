from datetime import datetime
from eth_account.messages import encode_defunct

from pydantic import BaseModel, Field


SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def create_signable_message(msg):
    """
    To be removed, used for testing
    """
    return encode_defunct(text=msg)


def create_transaction_message(value):
    """
    To be removed, used for testing
    """
    print(value)


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="TargetKeyId")
    creation: datetime = Field(alias="CreationDate")
    last_updated: datetime = Field(alias="LastUpdatedDate")
