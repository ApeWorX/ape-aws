"""Pytest configuration and fixtures for ape-aws tests."""

import pytest


@pytest.fixture
def networks():
    """Provides access to Ape networks."""
    import ape

    return ape.networks


@pytest.fixture
def accounts():
    """Provides access to Ape accounts."""
    import ape

    return ape.accounts


@pytest.fixture
def aws_account_container(accounts):
    """Provides the AWS account container for testing."""
    from ape_aws import AwsAccountContainer

    # Look for AWS account container in the accounts
    for container in accounts.containers.values():
        if isinstance(container, AwsAccountContainer):
            return container
    pytest.skip("AWS account container not available")


@pytest.fixture
def kms_account(aws_account_container):
    """Provides a KMS account for testing."""
    if not aws_account_container.accounts:
        pytest.skip("No KMS accounts available for testing")
    return list(aws_account_container.accounts)[0]
