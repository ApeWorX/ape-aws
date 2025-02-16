from ape.api import PluginConfig


class AwsConfig(PluginConfig):
    default_region: str | None = None
    default_profile: str | None = None
