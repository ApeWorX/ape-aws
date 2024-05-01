import boto3

from pydantic import BaseModel


class Client(BaseModel):
    client_name: str
    _client: boto3.client = None

    @property
    def client(self):
        if not self._client:
            self._client = boto3.client(self.client_name)
        return self._client


kms_client = Client(client_name='kms')
iam_client = Client(client_name='iam')
