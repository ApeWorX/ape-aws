# Ape AWS KMS

Ape plugin to make transactions through AWS KMS

## Dependencies

* [python3](https://www.python.org/downloads) version 3.7 or greater, python3-dev
* For the Ethereum Node for AWS to be created, some of the python dependencies MUST BE 
compiled and installed through Linux
* For the Lambda Function to be created, you MUST have docker installed

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

TODO: Describe library overview in code

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
[Node.js](https://nodejs.org/en/download/), 
[Python3](https://www.python.org/downloads/) and 
[pip](https://pip.pypa.io/en/stable/installation/) installed on your workstation
5. You must have the [AWS CDK Toolkit](https://docs.aws.amazon.com/cdk/v2/guide/cli.html)
6. You should setup the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install-linux.html)
   1. This is the best option for downloading docker and the SAM CLI

## AWS KMS Key Import Steps
For manual setup, follow this [article](https://aws.amazon.com/blogs/database/import-ethereum-private-keys-to-aws-kms/)

## License

This project is licensed under the [Apache 2.0](LICENSE).
