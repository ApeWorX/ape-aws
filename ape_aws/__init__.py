from ape import plugins

from .accounts import AwsAccountContainer, KmsAccount


@plugins.register(plugins.AccountPlugin)
def account_types():
    return AwsAccountContainer, KmsAccount
