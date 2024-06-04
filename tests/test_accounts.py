import pytest
from ape.types import MessageSignature, TransactionSignature
from ape_ethereum.transactions import StaticFeeTransaction
from eth_account.messages import encode_defunct

from ape_aws.accounts import AwsAccountContainer, KmsAccount


@pytest.fixture(scope="session")
def transaction():
    txn = {
        "chain_id": 11155111,
        "nonce": 0,
        "value": 1,
        "data": "0x00",
        "receiver": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
        "type": 0,
        "gas_limit": 1000000,
        "gas_price": 300000000000,
    }
    return StaticFeeTransaction(**txn)


@pytest.fixture(scope="session")
def string_message():
    return encode_defunct(text="12345")


@pytest.fixture(scope="session")
def aws_account_container():
    return AwsAccountContainer(name="ape-aws", account_type=KmsAccount)


@pytest.fixture(scope="session")
def kms_account(aws_account_container):
    return list(aws_account_container.accounts)[1]


def test_signing_message(kms_account, string_message):
    val = kms_account.sign_message(string_message)
    assert isinstance(val, MessageSignature)


def test_signing_transaction(kms_account, transaction):
    val = kms_account.sign_transaction(transaction)
    assert isinstance(val.signature, TransactionSignature)
