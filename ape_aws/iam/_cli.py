import boto3
import click


@click.group("iam")
def iam():
    """Manage AWS Admin information"""


@iam.command()
def list_admins():
    iam_client = boto3.client('iam')
    response = iam_client.list_users()
    admins = []
    for user in response['Users']:
        user_name = user['UserName']
        user_policies = iam_client.list_attached_user_policies(UserName=user_name)
        for policy in user_policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AdministratorAccess':
                admins.append(user_name)

    click.echo(f'Administrators: {admins}')


@iam.command()
def list_users():
    iam_client = boto3.client('iam')
    response = iam_client.list_users()
    click.echo(f'Users: {response.get("Users")}')
