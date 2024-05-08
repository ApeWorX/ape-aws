# Ape AWS KMS

Ape plugin to make transactions through AWS KMS

## Dependencies
- [python3](https://www.python.org/downloads) version 3.10 or greater, python3-dev

## Installation

### via `pip`

You can install the latest release via [`pip`](https://pypi.org/project/pip/):

```bash
pip install <PYPI_NAME>
```

### via `setuptools`

You can clone the repository and use [`setuptools`](https://github.com/pypa/setuptools) for the most up-to-date version:

```bash
git clone https://github.com/ApeWorX/<PYPI_NAME>.git
cd <PYPI_NAME>
python3 setup.py install
```

## Quick Usage

```bash
pip install ape-aws
```

### Using CLI tool

List commands:

```bash
ape aws -h
```

To create a new key:

```bash
ape aws kms create 'KeyAlias' 'Description of new key'
```

To delete this key:

```bash
ape aws kms delete 'KeyAlias'
```

### IPython

First, create a KMS key with the CLI tool

```bash
ape console
```

```python
In [1]: kms_acct = accounts.load("KeyAlias")
In [2]: kms_acct.sign_message("12345")
Out[2]: <MessageSignature v=27, r=0x..., s=0x...>
```

## Development

This project is in development and should be considered a beta.
Things might not be in their final state and breaking changes may occur.
Comments, questions, criticisms and pull requests are welcomed.

## Prerequisites to AWS Setup

To begin, create a virtual environment set up and activate the virtual environment before doing anything for the setup of AWS

1. You must have an AWS account
2. Must be an AWS Identity and Access Management (IAM) user with administrator access
3. Must have configured AWS credentials
4. Must have [Docker](https://docs.docker.com/get-docker/),
   [Python3](https://www.python.org/downloads/) and
   [pip](https://pip.pypa.io/en/stable/installation/) installed on your workstation

## AWS KMS Key Import Steps

For manual setup, follow this [article](https://aws.amazon.com/blogs/database/import-ethereum-private-keys-to-aws-kms/)

## License

This project is licensed under the [Apache 2.0](LICENSE).
