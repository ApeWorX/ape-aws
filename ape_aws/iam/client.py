import json
from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar

from botocore.exceptions import BotoCoreError  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, model_validator

from ape_aws.exceptions import AwsAccessError
from ape_aws.session import Session

if TYPE_CHECKING:
    from botocore.client import BaseClient  # type: ignore[import-untyped]


class IamPolicy(BaseModel):
    arn: str = Field(alias="PolicyArn")
    name: str = Field(alias="PolicyName")

    @model_validator(mode="before")
    @classmethod
    def patch_policy(cls, p: dict) -> dict:
        if "Arn" in p and "PolicyArn" not in p:
            p["PolicyArn"] = p.pop("Arn")

        return p


class IamAccessKey(BaseModel):
    id: str = Field(alias="AccessKeyId")
    status: str = Field(alias="Status")
    creation: datetime = Field(alias="CreateDate")
    secret_key: str | None = Field(default=None, alias="SecretAccessKey")

    def to_environment(self) -> str:
        if not self.secret_key:
            raise ValueError("Cannot view access key after creation, please delete and try again.")
        # NOTE: This matches up with loading code from `.session.Session.__init__`
        return f"AWS_ACCOUNT_ID={self.id}\nAWS_SECRET_KEY={self.secret_key}"


class IamUser(BaseModel):
    iam_client: ClassVar["BaseClient"]

    id: str = Field(alias="UserId")
    arn: str = Field(alias="Arn")
    name: str = Field(alias="UserName")
    creation: datetime = Field(alias="CreateDate")

    @cached_property
    def policies(self) -> dict[str, IamPolicy]:
        result = self.iam_client.list_attached_user_policies(UserName=self.name)
        policies = map(IamPolicy.model_validate, result["AttachedPolicies"])
        return {policy.name: policy for policy in policies}

    def add_policy(self, policy: IamPolicy):
        self.iam_client.attach_user_policy(UserName=self.name, PolicyArn=policy.arn)
        self.policies.update({policy.name: policy})  # update cache

    def remove_policy(self, policy: IamPolicy):
        self.iam_client.detach_user_policy(UserName=self.name, PolicyArn=policy.arn)
        del self.policies[policy.name]  # update cache

    @property
    def is_admin(self) -> bool:
        return self.policies.get("AdministratorAccess") is not None

    @cached_property
    def access_keys(self) -> dict[str, IamAccessKey]:
        response = self.iam_client.list_access_keys(UserName=self.name)
        access_keys = map(IamAccessKey.model_validate, response["AccessKeyMetadata"])
        return {key.id: key for key in access_keys}

    def create_access_key(self) -> IamAccessKey:
        response = self.iam_client.create_access_key(UserName=self.name)
        key = IamAccessKey.model_validate(response["AccessKey"])
        self.access_keys.update({key.id: key})  # Update cache
        return key

    def delete_access_key(self, key_id: str):
        key = self.access_keys.pop(key_id)  # Remove from cache
        self.iam_client.delete_access_key(UserName=self.name, AccessKeyId=key.id)

    def delete(self):
        while len(self.access_keys) > 0:
            self.delete_access_key(list(self.access_keys)[0])

        while len(self.policies) > 0:
            self.remove_policy(list(self.policies.values())[0])

        self.iam_client.delete_user(UserName=self.name)


class IamClient(Session):
    """AWS Client API for working with IAM Accounts"""

    KEY_POLICY_NAME = "ApeAwsKeyAccessV1"
    KEY_ACCESS_POLICY = dict(
        Sid="ApeAWSv1",
        Effect="Allow",
        Action=["kms:ListAliases", "kms:Sign", "kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"],
        Resource="*",
    )

    @cached_property
    def iam_client(self):
        client = self.session.client("iam")
        IamUser.iam_client = client  # DI
        return client

    @cached_property
    def users(self) -> dict[str, IamUser]:
        try:
            response = self.iam_client.list_users()

        except BotoCoreError as e:
            # NOTE: Handle here since `.users` is the main access point for the external API
            raise AwsAccessError(e) from e

        users = map(IamUser.model_validate, response.get("Users", []))

        return {user.name: user for user in users}

    def create_user(self, user_name: str) -> IamUser:
        result = self.iam_client.create_user(UserName=user_name)
        user = IamUser.model_validate(result["User"])
        self.users.update({user.name: user})  # Update cache
        return user

    def delete_user(self, user_name: str):
        user = self.users.pop(user_name)  # Remove from cache
        user.delete()

    @cached_property
    def policies(self) -> dict[str, IamPolicy]:
        result = self.iam_client.list_policies()
        policies = map(IamPolicy.model_validate, result["Policies"])
        return {policy.name: policy for policy in policies}

    def create_key_policy(self) -> IamPolicy:
        response = self.iam_client.create_policy(
            PolicyName=self.KEY_POLICY_NAME,
            PolicyDocument=json.dumps(
                dict(
                    Version="2012-10-17",
                    Statement=[self.KEY_ACCESS_POLICY],
                )
            ),
        )

        policy = IamPolicy.model_validate(response["Policy"])
        self.policies.update({policy.name: policy})  # Update cache
        return policy
