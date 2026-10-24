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


def __getattr__(name: str):
    """Lazy load module attributes for better import performance."""
    if name == "AwsConfig":
        from .config import AwsConfig

        return AwsConfig
    if name == "AwsAccountContainer":
        from .accounts import AwsAccountContainer

        return AwsAccountContainer
    if name == "KmsAccount":
        from .accounts import KmsAccount

        return KmsAccount
    if name == "AwsClient":
        from .client import AwsClient

        return AwsClient
    if name == "Session":
        from .session import Session

        return Session
    if name == "KmsClient":
        from .kms.client import KmsClient

        return KmsClient
    if name == "IamClient":
        from .iam.client import IamClient

        return IamClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AwsConfig",
    "AwsAccountContainer",
    "KmsAccount",
    "AwsClient",
    "Session",
    "KmsClient",
    "IamClient",
]
