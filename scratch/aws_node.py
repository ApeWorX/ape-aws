import boto3
from typing import Optional


class AwsNode:

    def __init__(
            self,
            client_request_token: Optional[str] = None,
            member_id: Optional[str] = None,
            network_id: str = 'n-ethereum-rinkeby',
            instance_type: str = 'bc.t3.large',
            availability_zone: str = 'us-east-1a'
    ):
        self.client = boto3.client('managedblockchain')
        self.client_request_token = client_request_token
        self.member_id = member_id
        self.network_id = network_id
        self.instance_type = instance_type
        self.availability_zone = availability_zone

    def create_node(self):
        if self.client_request_token and self.member_id:
            return self.client.create_node(
                ClientRequestToken=self.client_request_token,
                NetworkId=self.network_id,
                MemberId=self.member_id,
                NodeConfiguration={
                    'InstanceType': self.instance_type,
                    'AvailabilityZone': self.availability_zone,
                    # 'LogPublishingConfiguration': {
                    #     'Fabric': {
                    #         'ChaincodeLogs': {
                    #             'Cloudwatch': {
                    #                 'Enabled': True|False
                    #             }
                    #         },
                    #         'PeerLogs': {
                    #             'Cloudwatch': {
                    #                 'Enabled': True|False
                    #             }
                    #         }
                    #     }
                    # },
                    # 'StateDB': 'LevelDB' | 'CouchDB'
                },
                # Tags={
                #     'string': 'string'
                # }
            )
        elif self.member_id:
            return self.client.create_node(
                NetworkId=self.network_id,
                MemberId=self.member_id,
                NodeConfiguration={
                    'InstanceType': self.instance_type,
                    'AvailabilityZone': self.availability_zone,
                },
            )
        elif self.client_request_token:
            return self.client.create_node(
                ClientRequestToken=self.client_request_token,
                NetworkId=self.network_id,
                NodeConfiguration={
                    'InstanceType': self.instance_type,
                    'AvailabilityZone': self.availability_zone,
                },
            )
        else:
            return self.client.create_node(
                NetworkId=self.network_id,
                NodeConfiguration={
                    'InstanceType': self.instance_type,
                    'AvailabilityZone': self.availability_zone,
                },
            )
