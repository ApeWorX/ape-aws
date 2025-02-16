# Ape AWS KMS

Ape plugin to make transactions through AWS KMS

## Dependencies
- [python3](https://www.python.org/downloads) version 3.10 or greater, python3-dev

## Installation

### via `pip`

You can install the latest release via [`pip`](https://pypi.org/project/pip/):

```bash
pip install ape-aws
```

### via `setuptools`

You can clone the repository and use [`setuptools`](https://github.com/pypa/setuptools) for the most up-to-date version:

```bash
git clone https://github.com/ApeWorX/ape-aws.git
cd ape-aws
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

See logged in profile (useful for debugging auth in containers)

```bash
ape aws whoami
```

To create a new user (recommended for cloud usage)

```bash
ape aws users new USER
```

To delete this user (WARNING this is permanent)

```bash
ape aws users remove USER
```

Create an access key for this user (WARNING don't lose generated token)

```bash
ape aws users tokens new USER > .env.USER
```

To create a new Ethereum signing key (recommended to generate)

```bash
ape aws keys generate KEY
```

To schedule this signing key for deletion (WARNING takes 30 days)

```bash
ape aws keys remove KEY
```

To grant your user access to the signing key (don't forget to do this!)

```bash
ape aws keys grant KEY -u USER
```



### IPython

First, create a KMS key with the CLI tool

```bash
ape console
```

```python
In [1]: kms_signer = accounts.load("KEY")
In [2]: kms_signer.sign_message("12345")
Out[2]: <MessageSignature v=27, r=0x..., s=0x...>
```

Now to test your new IAM user's access, you can do the following

```bash
env $(echo .env.USER | xargs) ape console
```

and you should be able to do the same as the above!

Use the access token above to run with your containers by supplying them as environment variables

WARNING: Don't forget to cycle your access tokens on a regular basis to prevent access leakage!

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

## AWS Setup

#### For Mac and Linux
Create a `~/.aws` folder in your home directory:
```bash
mkdir ~/.aws
```

Note: get your access key and key id from your IAM in you AWS account [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).
Create a `credentials` file in the `~/.aws` folder:
```bash
cat <<EOF > ~/.aws/credentials
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET
EOF
```

Create a `config` file in the `~/.aws` folder:
```bash
cat <<EOF > ~/.aws/config
[default]
region = YOUR_REGION
output = json
EOF
```

## AWS KMS Key Import Steps

For manual setup, follow this [article](https://aws.amazon.com/blogs/database/import-ethereum-private-keys-to-aws-kms/)

## License

This project is licensed under the [Apache 2.0](LICENSE).
