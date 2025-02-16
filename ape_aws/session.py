import os
from typing import TYPE_CHECKING, ClassVar

from ape.utils import ManagerAccessMixin
from boto3 import Session as AwsSession  # type: ignore[import-untyped]
from botocore.exceptions import NoCredentialsError, ProfileNotFound  # type: ignore[import-untyped]

from ape_aws.exceptions import ApeAwsException

if TYPE_CHECKING:
    from .config import AwsConfig


# NOTE: Subclass this w/ other clients to access `.session`
class Session(ManagerAccessMixin):
    """Helper for loading AWS Session profile w/ Ape Config"""

    session: ClassVar[AwsSession]

    @property
    def config(self) -> "AwsConfig":
        return self.config_manager.get_config("aws")

    def __init__(self, profile_name: str | None = None):
        session_kwargs: dict[str, str] = {}

        if profile_name is not None:
            session_kwargs["profile_name"] = profile_name

        elif (account_id := os.environ.get("AWS_ACCOUNT_ID")) and (
            secret_key := os.environ.get("AWS_SECRET_KEY")
        ):
            session_kwargs["aws_access_key_id"] = account_id
            session_kwargs["aws_secret_access_key"] = secret_key

        elif profile_envvar := os.environ.get("AWS_PROFILE"):
            session_kwargs["profile_name"] = profile_envvar

        elif self.config.default_profile:
            session_kwargs["profile_name"] = self.config.default_profile

        else:
            session_kwargs["profile_name"] = "default"

        if region_name := os.environ.get("AWS_DEFAULT_REGION"):
            session_kwargs["region_name"] = region_name

        elif self.config.default_region:
            session_kwargs["region_name"] = self.config.default_region

        else:
            session_kwargs["region_name"] = "us-east-1"

        try:
            self.__class__.session = AwsSession(**session_kwargs)

        except (NoCredentialsError, ProfileNotFound) as e:
            raise ApeAwsException(str(e)) from e
