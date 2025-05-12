from functools import cached_property
from typing import Any, Iterator, Optional

from ape.api import AccountAPI, AccountContainerAPI, TransactionAPI
from ape.logging import logger
from ape.types import AddressType, MessageSignature, SignableMessage, TransactionSignature
from eip712 import EIP712Message
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_pydantic_types import HexBytes
from eth_typing import Hash32

from ape_aws.exceptions import ApeAwsException

from .client import AwsClient
from .exceptions import AwsAccessError
from .kms.client import KmsKey
from .utils import _convert_der_to_rsv


class AwsAccountContainer(AwsClient, AccountContainerAPI):
    def __init__(self, *args, **kwargs):
        super(AwsClient, self).__init__()  # NOTE: Use config/envvar default
        super(AccountContainerAPI, self).__init__(*args, **kwargs)

    @property
    def keys(self) -> dict[str, KmsKey]:  # type: ignore[syntax]
        try:
            keys = super(AwsClient, self).keys

        except AwsAccessError as e:
            # NOTE: Do not raise here, instead just log warning (prevent issues w/ Ape API)
            logger.warning(str(e))
            return {}

        return {alias: key for alias, key in keys.items() if key.enabled}

    @property
    def aliases(self) -> Iterator[str]:
        yield from iter(self.keys)

    def __len__(self) -> int:
        return len(self.keys)

    @property
    def accounts(self) -> Iterator[AccountAPI]:
        return map(lambda key: KmsAccount(key=key), self.keys.values())


class KmsAccount(AccountAPI):
    key: KmsKey

    @property
    def alias(self) -> str:
        return self.key.alias

    @cached_property
    def address(self) -> AddressType:
        return self.key.address

    def sign_raw_msghash(self, msghash: HexBytes | Hash32) -> Optional[MessageSignature]:
        if len(msghash) != 32:
            return None

        if not (signature := self.key.sign(msghash)):
            return None

        msg_sig = MessageSignature(**_convert_der_to_rsv(signature, 27))
        if not self.check_signature(msghash, msg_sig, recover_using_eip191=False):
            # NOTE: Best way to determine parity is just to try recovery
            msg_sig = MessageSignature(v=msg_sig.v + 1, r=msg_sig.r, s=msg_sig.s)

        return msg_sig

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        if isinstance(msg, SignableMessage):
            message = msg

        elif isinstance(msg, EIP712Message):
            message = msg.signable_message

        elif isinstance(msg, str):
            if msg.startswith("0x"):
                message = encode_defunct(hexstr=msg)
            else:
                message = encode_defunct(text=msg)
        elif isinstance(msg, bytes):
            message = encode_defunct(primitive=msg)
        else:
            raise ApeAwsException(f"Cannot sign {type(msg)}")

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
        txn_dict = txn.model_dump()
        # NOTE: remove this so doesn't raise below
        txn_dict.pop("from", None)
        unsigned_txn_hash = serializable_unsigned_transaction_from_dict(txn_dict).hash()

        if not (signature := self.sign_raw_msghash(HexBytes(unsigned_txn_hash))):
            return None

        # NOTE: We already added 27 to v above, so substract it from v to normalize to {0,1}
        v = signature.v - 27
        if txn.chain_id and txn.type == 0:
            # Include 155 chain ID protection offset
            v += (2 * txn.chain_id) + 35

        txn.signature = TransactionSignature(v=v, r=signature.r, s=signature.s)
        return txn
