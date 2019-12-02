# setup-new-aws-user

This script creates a virtual MFA device and rotates access keys for a new AWS user.

## Installation

Installation instructions will go here.

## Usage

The script requires the following environment variables to be set:

|Name|Description|
|----|-----------|
|AWS_ACCOUNT_ID|AWS account number corresponding to the AWS_PROFILE account|
|AWS_PROFILE|Alias for the account where this script is being run|
|AWS_ID_PROFILE|Alias of the ID account for the organization|

For testing purposes, set these variables in a .envrc.local file.

For regular users, AWS_PROFILE and AWS_ID_PROFILE should be identical.

Run the following command to execute the script:

    go run cmd/main.go --role <ROLE> --iam_user <USER>

## Dev setup

1. First, install these packages:
   - `brew install pre-commit`
   - `brew install direnv`
1. Next, clone the project repository.
1. Finally, run these commands inside the local repo:
   - `pre-commit install --install-hooks`
   - `direnv allow`
1. The `.envrc` will be loaded if `direnv` is installed.
