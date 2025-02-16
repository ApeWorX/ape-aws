from typing import TYPE_CHECKING

import click

from ape_aws.exceptions import ApeAwsException

from .iam import IamClient
from .kms import KmsClient
from .session import Session

if TYPE_CHECKING:
    from click import Context


# NOTE: Full AWS Client is far too complicated to try to include in one class
class AwsClient(IamClient, KmsClient, Session):
    """The fully assembled AWS Client"""

    @classmethod
    def _click_argument_callback(cls, ctx: "Context", arg: str, value: str | None) -> "AwsClient":
        try:
            return cls(value)
        except ApeAwsException as e:
            raise click.BadOptionUsage("profile", str(e))
