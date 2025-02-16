from functools import cached_property
from typing import Any, Iterator, Optional

from ape.api.accounts import AccountAPI, AccountContainerAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, SignableMessage, TransactionSignature
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_pydantic_types import HexBytes
from eth_typing import Hash32

from ape_aws.exceptions import ApeAwsException

from .client import AwsClient
from .kms.client import KmsKey
from .utils import _convert_der_to_rsv


class AwsAccountContainer(AwsClient, AccountContainerAPI):
    def __init__(self, *args, **kwargs):
        super(AwsClient, self).__init__()  # NOTE: Use config/envvar default
        super(AccountContainerAPI, self).__init__(*args, **kwargs)

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
        # TODO: Figure out how to properly compute v in `_convert_der_to_rsv`
        if not self.check_signature(msghash, msg_sig, recover_using_eip191=False):
            msg_sig = MessageSignature(v=msg_sig.v + 1, r=msg_sig.r, s=msg_sig.s)

        return msg_sig

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        if isinstance(msg, SignableMessage):
            message = msg
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
        unsigned_txn = serializable_unsigned_transaction_from_dict(txn_dict).hash()

        if not (msg_sig := self.sign_raw_msghash(HexBytes(unsigned_txn))):
            return None

        txn.signature = TransactionSignature(
            # Include 155 chain ID protection
            # NOTE: We already added 27 above
            # v=((msg_sig.v - 27) + (2 * txn.chain_id) + 35) if txn.chain_id else msg_sig.v,
            v=msg_sig.v - 27,
            # TODO: Figure out why EIP 155 protection isn't working right...
            r=msg_sig.r,
            s=msg_sig.s,
        )

        return txn
