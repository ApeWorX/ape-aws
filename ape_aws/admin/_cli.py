import boto3
import click


@click.group("admin")
def admin():
    """Manage AWS Admin information"""


@admin.command()
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


@admin.command()
def list_users():
    iam_client = boto3.client('iam')
    response = iam_client.list_users()
    click.echo(f'Users: {response.get("Users")}')


@admin.command()
@click.option('--dictionary', '-d', multiple=True)
def check_this(dictionary):
    print(dictionary)
