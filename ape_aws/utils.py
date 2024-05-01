import ecdsa
from datetime import datetime

from pydantic import BaseModel, Field


SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def _convert_der_to_rsv(
    signature: bytes, v_adjustment_factor: int = 0
) -> dict:
    breakpoint()
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
    v = signature[0] + v_adjustment_factor
    if s > SECP256_K1_N / 2:
        s = SECP256_K1_N - s
        print('s > SEC')
    if r > SECP256_K1_N / 2:
        print('r > SEC')
    r = r.to_bytes(32, byteorder='big')
    s = s.to_bytes(32, byteorder='big')
    return dict(v=v, r=r, s=s)


class AliasResponse(BaseModel):
    alias: str = Field(alias="AliasName")
    arn: str = Field(alias="AliasArn")
    key_id: str = Field(alias="TargetKeyId")
    creation: datetime = Field(alias="CreationDate")
    last_updated: datetime = Field(alias="LastUpdatedDate")
