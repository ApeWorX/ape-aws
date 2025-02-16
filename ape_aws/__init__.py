from ape import plugins


@plugins.register(plugins.Config)
def config_class():
    from .config import AwsConfig

    return AwsConfig


@plugins.register(plugins.AccountPlugin)
def account_types():
    from .accounts import AwsAccountContainer, KmsAccount

    AwsAccountContainer.model_rebuild()
    return AwsAccountContainer, KmsAccount
