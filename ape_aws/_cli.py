from collections import defaultdict

import click

from ape_aws.client import AwsClient


def _click_profile_option(argument_name):

    return click.option(
        "-p",
        "--profile",
        argument_name,
        default=None,
        callback=AwsClient._click_argument_callback,
        help=(
            "AWS profile to use to run this command "
            "(set default via Ape config, or use `AWS_PROFILE_ID`)"
        ),
    )


@click.group()
def cli():
    """
    Configure AWS Accounts and Signing Keys for use with Ape

    This command helps you to create AWS IAM accounts with the proper permissions to use as a
    remote signer, as well as create keys in AWS KMS that those accounts can access to sign with
    via Ape. The goal of this plugin is to configure a cloud environment to use for automation,
    such as running on the Silverback Platform or other production use cases.

    To begin, start with `ape aws whoami` to make sure your AWS account is properly loaded.
    """


@cli.command()
@_click_profile_option("client")
def whoami(client: AwsClient):
    """Display profile information of logged-in account"""
    click.echo(f"Region: {client.session.region_name}")
    click.echo(f"Profile: {client.session.profile_name}")
    creds = client.session.get_credentials()
    click.echo(f"Access Key: {creds.access_key}")


@cli.command()
@_click_profile_option("client")
def policies(client: AwsClient):
    """List all available policies

    Note that if you want to create a new policy, it is recommended to do so through AWS console,
    or the `aws` cli.
    """
    if policies := "\n".join(
        f"{policy.name} ({policy.arn})" for policy in client.policies.values()
    ):
        click.echo(policies)


@cli.group()
def users():
    """Commands for configuring IAM Users, Policies, and more"""


@users.command(name="list")
@_click_profile_option("client")
def list_user(client: AwsClient):
    """Display available users accessible with the logged in profile"""
    if users := "\n".join(f"{user.name} ({user.arn})" for user in client.users.values()):
        click.echo(users)

    else:
        raise click.UsageError(
            "No users available under profile '{aws_client.profile}'.\n\n"
            "Try `ape aws add-user` to create a new signer, or switch profiles."
        )


@users.command(name="new")
@_click_profile_option("client")
@click.option("-p", "--policy", "policy_names", multiple=True, help="Name of a valid policy")
@click.argument("name")
def add_user(client: AwsClient, policy_names: list[str], name: str):
    """Add a new IAM user NAME under the logged in profile

    Note that you can also add policies to this IAM user through the `--policy` option
    """
    user = client.create_user(name)
    click.echo(f"Created {user.name} ({user.arn})")

    if client.KEY_POLICY_NAME not in client.policies:
        key_policy = client.create_key_policy()
        click.echo(f"Policy '{key_policy.name}' added.")
        policy_names = [*policy_names, key_policy.name]

    elif client.KEY_POLICY_NAME not in policy_names:
        policy_names = [*policy_names, client.KEY_POLICY_NAME]

    for policy_name in policy_names:
        if not (policy := client.policies.get(policy_name)):
            click.echo(f"'{policy_name}' is not a valid policy name", err=True)
            continue

        user.add_policy(policy)
        click.echo(f"Policy '{policy.name}' added to user '{user.name}'.")


@users.command(name="remove")
@_click_profile_option("client")
@click.argument("name")
def remove_user(client: AwsClient, name: str):
    """Remove IAM user NAME under the logged in profile"""
    if not (user := client.users.get(name)):
        raise click.UsageError(f"'{name}' is not an available IAM Account")

    user.delete()
    click.echo(f"Removed {user.name} ({user.arn})")


@users.group()
def tokens():
    """Commands for configuring access tokens for an IAM user"""


@tokens.command(name="list")
@_click_profile_option("client")
@click.argument("name")
def list_access_tokens(client: AwsClient, name: str):
    """List access tokens for the IAM user NAME"""
    if not (user := client.users.get(name)):
        raise click.UsageError(f"'{name}' is not an available IAM Account")

    if keys := "\n".join(
        f"{key.id} ({key.status}) - Created: {key.creation}" for key in user.access_keys.values()
    ):
        click.echo(keys)


@tokens.command(name="new")
@_click_profile_option("client")
@click.argument("name")
def new_access_token(client: AwsClient, name: str):
    """Create an access token for the IAM user NAME

    Note that you cannot view this key after it is generated, so please store it carefully.
    Also note that this access key gives full access to the IAM account it is generated for.

    You can use this key to automatically grant access to the IAM account it is generated for
    via the environment variables mentioned when called (e.g. in a containerized environment).
    """
    if not (user := client.users.get(name)):
        raise click.UsageError(f"'{name}' is not an available IAM Account")

    access_key = user.create_access_key()

    # NOTE: Do these to `err=True` so you can do `ape aws users access-key new ALIAS > .env`
    click.secho(f"SUCCESS: Access key created for '{name}'", fg="green", err=True)
    click.secho(
        "WARNING: Access key will not be available after this command", fg="bright_yellow", err=True
    )
    click.echo(access_key.to_environment())


@tokens.command(name="remove")
@_click_profile_option("client")
@click.argument("name")
@click.argument("key_id")
def remove_access_token(client: AwsClient, name: str, key_id: str):
    """Remove access token KEY_ID for the IAM user NAME"""
    if not (user := client.users.get(name)):
        raise click.UsageError(f"'{name}' is not an available IAM Account")

    if not user.access_keys.get(key_id):
        raise click.UsageError(f"'{key_id}' is not an available Access Key for {user.name}")

    user.delete_access_key(key_id)
    click.secho(f"Access key {key_id} removed from {user.name}", fg="green")


@cli.group()
def keys():
    """Commands for creating and managing KMS keys, access controls, and more

    It is recommended that you use `ape aws users` to create a new IAM account with the
    correct attached policies needed to use KMS and perform key signing via Ape.
    """


@keys.command(name="list")
@_click_profile_option("client")
def list_keys(client: AwsClient):
    """List all keys available to account"""
    if keys := "\n".join(f"'{key.alias}' (id: {key.id})" for key in client.keys.values()):
        click.echo(keys)


@keys.command()
@_click_profile_option("client")
@click.option(
    "-u",
    "--user",
    "user_names",
    multiple=True,
    help="Give access to key for one or more users, ex. -u NAME1, -u NAME2",
)
@click.argument("alias")
def generate(client: AwsClient, user_names: list[str], alias: str):
    """Generate a new key ALIAS and grant access to USERS and ADMINS"""
    key = client.generate_key(alias)
    click.echo(f"Key created '{key.id}'.")

    users = []
    for user_name in user_names:
        if not (user := client.users.get(user_name)):
            click.echo(f"'{user_name}' is not a valid user name for an admin", err=True)
            continue

        users.append(user)

    key.set_policy(users_to_add=[u.arn for u in users])
    click.secho(f"Key policies updated for {key.alias}", fg="green", err=True)


@keys.command(name="show")
@_click_profile_option("client")
@click.argument("alias")
def show_key_info(client: AwsClient, alias: str):
    """Show info about key ALIAS, including Admins and Users"""
    if not (key := client.keys.get(alias)):
        raise click.UsageError(f"'{alias}' is not an available key alias")

    key_policy = key.get_policy()
    access_rights: dict[str, dict[str, str | list[str]]] = defaultdict(dict)
    for stmt in key_policy["Statement"]:
        if (arn := stmt["Principal"]["AWS"]).endswith("root"):
            continue

        for user in client.users.values():
            if user.arn == arn:
                access_rights[arn][stmt["Resource"]] = stmt["Action"]
                break

        else:
            click.echo(f"Unrecognized ARN: {arn}", err=True)

    for user_arn, key_access in access_rights.items():
        click.echo(f"{user_arn}:")
        for key_arn, rights in key_access.items():
            if isinstance(rights, list):
                rights = ", ".join(rights)
            click.echo(f"  {key_arn}: {rights}")


@keys.command(name="grant")
@_click_profile_option("client")
@click.option(
    "-u",
    "--user",
    "user_names",
    multiple=True,
    help="Give access to key for one or more users, ex. -u NAME1, -u NAME2",
)
@click.argument("alias")
def grant_key_access(client: AwsClient, user_names: list[str], alias: str):
    """Grant access to USERS and ADMINS for key ALIAS"""
    if not (key := client.keys.get(alias)):
        raise click.UsageError(f"'{alias}' is not an available key alias")

    users = []
    for user_name in user_names:
        if not (user := client.users.get(user_name)):
            click.echo(f"'{user_name}' is not a valid user name for an admin", err=True)
            continue

        users.append(user)

    key.set_policy(users_to_add=[u.arn for u in users])
    click.secho(f"Key policies updated for {key.alias}", fg="green", err=True)


@keys.command(name="revoke")
@_click_profile_option("client")
@click.option(
    "-u",
    "--user",
    "user_names",
    multiple=True,
    help="Give access to key for one or more users, ex. -u NAME1, -u NAME2",
)
@click.argument("alias")
def revoke_key_access(client: AwsClient, user_names: list[str], alias: str):
    """Revoke access to USERS and ADMINS for key ALIAS"""
    if not (key := client.keys.get(alias)):
        raise click.UsageError(f"'{alias}' is not an available key alias")

    users = []
    for user_name in user_names:
        if not (user := client.users.get(user_name)):
            click.echo(f"'{user_name}' is not a valid user name for an admin", err=True)
            continue

        users.append(user)

    key.set_policy(users_to_remove=[u.arn for u in users])
    click.secho(f"Key policies updated for {key.alias}", fg="green", err=True)
