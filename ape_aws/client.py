import boto3

from pydantic import BaseModel

from ape.utils import cached_property


class Client(BaseModel):
    @cached_property
    def kms_client(self):
        return boto3.client('kms')

    @cached_property
    def iam_client(self):
        return boto3.client('iam')


client = Client()
