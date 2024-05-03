from ape.types import MessageSignature


def test_signing_message(kms_account, string_message):
    val = kms_account.sign_message(string_message)
    assert isinstance(val, MessageSignature)
