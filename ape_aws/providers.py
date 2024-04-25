from ape.api import (
    ConfigItem,
    Web3Provider,
    ProviderAPI,
)
from typing import Optional


class ApeAwsKmsForkConfig(ConfigItem):
    upstream_provider: Optional[str] = None


class ApeAwsKmsProvider(Web3Provider, ProviderAPI):
    pass