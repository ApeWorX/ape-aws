import click

from ape_aws.client import iam_client


@click.group("iam")
def iam():
    """Manage AWS Admin information"""


@iam.command()
def list_admins():
    response = iam_client.client.list_users()
    admins = []
    for user in response['Users']:
        user_name = user['UserName']
        user_policies = iam_client.client.list_attached_user_policies(UserName=user_name)
        for policy in user_policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AdministratorAccess':
                admins.append(user_name)

    click.echo(f'Administrators: {admins}')


@iam.command()
def list_users():
    response = iam_client.client.list_users()
    click.echo(f'Users: {response.get("Users")}')
