# setup-new-aws-user

This script creates a virtual MFA device and rotates access keys for a new AWS user.

## Installation

For OSX Homebrew:

```shell
brew tap trussworks/tap
brew install setup-new-aws-user
```

## Usage

The script accepts a number of arguments, either as environment variables or
command-line flags:

```text
Usage:
  main [OPTIONS]
  Application Options:
    --region=     The AWS region (default: us-west-2) [$AWS_REGION]
    --account-id= The AWS account number [$AWS_ACCOUNT_ID]
    --profile=    The AWS profile name [$AWS_PROFILE]
    --iam-user=   The IAM user name
    --role=       The user role type
    --output=     The AWS CLI output format (default: json)
  Help Options:
    -h, --help        Show this help message
```

For the arguments that accept either an environment variable or command-line
flag, the environment variable takes precedence if both are provided due to the
way go-flags works.

### Setup new IAM user

1. Have admin user run through
[these instructions](https://github.com/trussworks/legendary-waddle/blob/master/docs/how-to/setup-new-user.md#existing-admin-user-does-this)
in legendary-waddle repo to generate access keys.
1. Set `AWS_ACCOUNT_ID` and `AWS_PROFILE` variables in one of three ways:
    - Save to an .envrc.local file
    - Set them as local environment variables on your terminal, or
    - Pass them through as flags when you run this script
    (i.e.
    `go run cmd/main.go --role <ROLE> --iam-user <USER> --profile=<AWS_PROFILE> --account-id=<AWS_ACCOUNT_ID>`)
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

### Testing

For testing, create a test IAM user so as not to interfere with your primary
user credentials and AWS config settings. The test user will need the
`enforce-mfa` policy and permission to assume whichever role being assigned.
Generate an access key for the user, and use those when running the script. For
the AWS profile, do not use an existing profile name. You can use a dummy name
for the profile; it doesn't need to match the account alias. However, you must
use the real AWS account ID.

Example:

```shell
go run cmd/main.go --role engineer --iam-user testuser --account-id 123456789012  --profile test-profile-name
```

After running the script, try a command to ensure the new profile works as
expected:

Example (include AWS_VAULT_KEYCHAIN_NAME if the environment variable is not
set):

```shell
AWS_VAULT_KEYCHAIN_NAME=login aws-vault exec test-profile-name -- aws sts get-caller-identity
```
