# setup-new-aws-user

This script creates a virtual MFA device and rotates access keys for a new AWS user.

## Installation

Installation instructions will go here.

## Usage

The script requires the following environment variables to be set:

|Name|Description|Example
|----|-----------|---------|
|AWS_ACCOUNT_ID|AWS account number corresponding to the AWS_PROFILE account|`123456789012`
|AWS_PROFILE|Alias for the account where this script is being run|`trussworks-id`

For testing purposes, set the above variables in a .envrc.local file.

### Setup new IAM user

1. Have admin user run through
[these instructions](https://github.com/trussworks/legendary-waddle/blob/master/docs/how-to/setup-new-user.md#existing-admin-user-does-this)
in legendary-waddle repo to generate access keys.
1. Set `AWS_ACCOUNT_ID` and `AWS_PROFILE` variables in one of three ways:
    - Save to an .envrc.local file
    - Set them as local environment variables on your terminal, or
    - Pass them through as flags when you run this script
    (i.e.
    `go run cmd/main.go --role <ROLE> --iam_user <USER> --profile=<AWS_PROFILE> --account-id=<AWS_ACCOUNT_ID>`)
1. Run the setup-new-user script: `go run cmd/main.go --role <ROLE> --iam_user <USER>`
1. Enter the access keys generated when prompted.
1. The script will display a QR code for an MFA device at some point.
Create an entry in your 1Password account with a One Time Password (OTP)
field and be ready to scan it with the 1Password app.
Currently works only with mobile app.

- **NOTE** You will be asked for your MFA (TOTP) tokens three times while
validating the new virtual MFA device and rotating your access keys.
**Take care not to use the same token
more than once**, as this will cause the process to fail.

## Dev setup

1. First, install these packages:
   - `brew install pre-commit`
   - `brew install direnv`
1. Next, clone the project repository.
1. Finally, run these commands inside the local repo:
   - `pre-commit install --install-hooks`
   - `direnv allow`
1. The `.envrc` will be loaded if `direnv` is installed.
