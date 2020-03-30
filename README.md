# setup-new-aws-user

This tool is used to grant programmatic access to AWS account(s) using
[aws-vault](https://github.com/99designs/aws-vault). It works by taking a
temporary set of AWS access keys for a new IAM user. It then generates a
virtual MFA device and permanent set of access keys. Finally, it removes
the temporary access keys.

## Installation

For Mac OS Homebrew:

```shell
brew tap trussworks/tap
brew install setup-new-aws-user
```

## Usage

### Prerequisites

#### Dependencies

```shell
brew cask install aws-vault
```

Before running this tool, you will need to following pieces of information

* IAM role - This is the IAM Role with permissions allowing access to AWS APIs
  and services. This is usually something like `admin` or `engineer`.
* IAM user name - This is your IAM username.
* AWS profile - This is the name that populates your `~/.aws/config` profile
  name. It is usually the name of the aws account alias you are trying to access.
* AWS account Id - This is the 12-digit account number of the AWS account you
  are trying to access.
* Temporary AWS access keys - These should be given to you by an administrator
  of the AWS account you are trying to access. The tool will prompt you for
  the access key id and secret access key.

## Running the tool

1. Run the setup-new-user - `setup-new-aws-user --role <IAM_ROLE> --iam_user <USER> --profile=<AWS_PROFILE> --account-id=<AWS_ACCOUNT_ID>`
2. Enter the access keys generated when prompted.
3. The script will open a window with a QR code, which you will use to configure
  a temporary one time password (TOTP).
4. Create an entry in your 1Password account field and be ready to scan it with the 1Password app.
**NOTE** You will be asked for your MFA (TOTP) tokens three times while
validating the new virtual MFA device and rotating your access keys.
**Take care not to use the same token
more than once**, as this will cause the process to fail.
5. Once the tool has completed, you should be able to access the AWS account. You can run the following

## Development setup

1. First, install these packages: `brew install pre-commit direnv go`
2. Next, clone the project repository.
3. Finally, run these commands inside the local repo: `direnv allow`
4. The `.envrc` will be loaded if `direnv` is installed.

### Testing

#### Unit Tests

Run pre-commit and Go tests

```shell
make test
```

#### Integration / End 2 End Testing

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
