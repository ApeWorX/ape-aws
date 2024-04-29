import ecdsa
from datetime import datetime
from eth_account.messages import encode_defunct

from pydantic import BaseModel, Field

from ape_ethereum.transactions import DynamicFeeTransaction


SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

txn = {
    "chain_id": 11155111,
    "nonce": 0,
    "value": 1,
    "data": '0x00',
    "receiver": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
    "type": 2,
    "max_fee": 100000000000,
    "max_priority_fee": 300000000000,
}

transaction = DynamicFeeTransaction(**txn)


def create_signable_message(msg):
    """
    To be removed, used for testing
    """
    return encode_defunct(text=msg)


def _convert_der_to_rsv(signature: bytes) -> dict:
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
    if s > SECP256_K1_N / 2:
        s = SECP256_K1_N - s
    r = r.to_bytes(32, byteorder='big')
    s = s.to_bytes(32, byteorder='big')
    return r, s


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="TargetKeyId")
    creation: datetime = Field(alias="CreationDate")
    last_updated: datetime = Field(alias="LastUpdatedDate")
