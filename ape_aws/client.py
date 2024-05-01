from typing import List

import boto3

from ape.utils import cached_property

from .utils import AliasResponse


class Client:

    def __init__(self, client_name: str):
        self.client_name = client_name
        self._client = None

    @property
    def client(self):
        if not self._client:
            self._client = boto3.client(self.client_name)
        return self._client


class KmsClient(Client):

    def __init__(self):
        super().__init__(client_name='kms')

    @cached_property
    def raw_aliases(self) -> List[AliasResponse]:
        paginator = self.client.get_paginator('list_aliases')
        pages = paginator.paginate()
        return [
            AliasResponse(**page)
            for alias_data in pages
            for page in alias_data['Aliases']
            if "alias/aws" not in page["AliasName"]
        ]

    def get_public_key(self, key_id: str):
        return self.client.get_public_key(KeyId=key_id)["PublicKey"]

    def sign(self, key_id, msghash):
        response = self.client.sign(
            KeyId=key_id,
            Message=msghash,
            MessageType='DIGEST',
            SigningAlgorithm='ECDSA_SHA_256',
        )
        return response.get('Signature')


class IamClient(Client):

    def __init__(self):
        super().__init__(client_name='iam')

    def list_users(self):
        result = iam_client.client.list_users()
        return result.get('Users')

    def list_admins(self):
        admins = []
        for user in self.list_users():
            user_name = user['UserName']
            user_policies = self.client.list_attached_user_policies(UserName=user_name)
            for policy in user_policies['AttachedPolicies']:
                if policy['PolicyName'] == 'AdministratorAccess':
                    admins.append(user_name)
        return admins


kms_client = KmsClient()
iam_client = IamClient()
