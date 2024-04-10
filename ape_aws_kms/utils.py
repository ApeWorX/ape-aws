import botocore
from typing import Any, Optional

from pydantic import (
    BaseModel,
    Field,
)
from hexbytes import HexBytes

from ape.types import SignableMessage

from eip712.messages import EIP712Message


class Transaction(BaseModel):
    nonce: int
    to: str
    value: int
    data: str = Field(default='0x00')
    gas: int = Field(default=160000)
    gas_price: str = Field(alias='gasPrice', default='0x0918400000')


class Message(BaseModel):
    msg: Any
    key_id: str
    client: botocore.client.KMS

    def sign(self) -> Optional[Any]:
        message = None
        if isinstance(self.msg, str):
            message = self.msg

        elif isinstance(self.msg, int):
            message = HexBytes(self.msg).hex()

        elif isinstance(self.msg, bytes):
            message = self.msg.hex()

        elif isinstance(self.msg, SignableMessage):
            message = self.msg.body

        elif isinstance(self.msg, EIP712Message):
            message = self.msg._body_

        if not message:
            return None

        response = self.client.sign(
            KeyId=self.key_id,
            Message=self.msg,
            MessageType='DIGEST',
            SigningAlgorithm='ECDSA_SHA_256',
        )
        return response

