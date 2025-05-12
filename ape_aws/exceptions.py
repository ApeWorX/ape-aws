from typing import TYPE_CHECKING

from ape.exceptions import ApeException
from click.exceptions import UsageError

if TYPE_CHECKING:
    from botocore.exceptions import BotoCoreError  # type: ignore[import-untyped]


class ApeAwsException(ApeException):
    pass  # NOTE: For subclassing


class AwsAccessError(ApeAwsException, UsageError):
    def __init__(self, exc: "BotoCoreError"):
        super().__init__(f"[ape-aws] {exc}")
