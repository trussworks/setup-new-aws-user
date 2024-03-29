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

### Dependencies

This tool requires aws-vault be installed. You can install via homebrew:

```shell
brew install aws-vault
```

## Usage

This tool has several subcommands. Read each section to learn more.

### setup-new-aws-user setup

Before running this tool, you will need to following pieces of information

- IAM user name - This is your IAM username. Use the flag `--iam-user` with this value.
- IAM role name - This is the IAM Role with permissions allowing access to AWS APIs
  and services. This is usually something like `admin` or `engineer`. Use the flag
  `--iam-role` with this value.
- AWS Region - This utility will default to "us-west-2" so if you are using this tool for GovCloud or other partitions you will need to provide a region specific to that partition.
- AWS Profiles and Account IDs - This is the set of aws profile names you wish to
  add along with the corresponding AWS account ID. They are referenced as
  `<AWS_PROFILE>:<AWS_ACCOUNT_ID>`. Use the flag name `--aws-profile-account`
  with each set you wish to add.
- Temporary AWS access keys - These should be given to you by an administrator
  of the AWS account you are trying to access. The tool will prompt you for
  the access key id and secret access key.

1. Run the setup-new-user script

   ```sh
   setup-new-aws-user setup \
     --iam-user <USER> \
     --iam-role <ROLE> \
     --aws-region <AWS_REGION> \
     --aws-profile-account <AWS_PROFILE1>:<AWS_ACCOUNT_ID1> \
     --aws-profile-account <AWS_PROFILE2>:<AWS_ACCOUNT_ID2>
   ```

2. Enter the access keys generated when prompted.
3. The script will open a window with a QR code, which you will use to configure a temporary one time password (TOTP).
4. You'll then need to create a new entry in your 1Password account configure it with a TOTP field.
5. Use 1Password to scan the QR code and hit save. New TOTP tokens should generate every 30 seconds.
6. From here the tool will prompt you for 3 unique TOTP tokens. **NOTE Take care not to use the same token more than once, as this will cause the process to fail.**
7. Once the tool has completed, you should be able to access the AWS account. You can run the following command filling in the `AWS_PROFILE` value

   ```sh
   aws-vault exec $AWS_PROFILE -- aws sts get-session
   ```

#### How `setup` modifies your ~/.aws/config

While your AWS access keys are stored in a password protected keychain managed by `aws-vault`, the configuration for
how you should access AWS accounts lives in ~/.aws/config. The `setup-new-aws-user setup` tool creates new profiles in
`~/.aws/config`. The first is the base profile containing your long lived AWS Access Keys and is tied to your IAM user
and MFA device. Since these keys are long lived, you should be rotating them regularly with `aws-vault rotate`.
The second profile is the IAM role granting you elevated access to the AWS account. Typically these IAM roles are
named `admin` or `engineer` and only uses temporary credentials leveraging AWS's Security Token Service (STS).
Below is an example config generated from this tool. Additional profiles will be similarly added and reference the
base profile.

```ini
[profile corp-id-base]
mfa_serial=arn:aws:iam::123456789012:mfa/alice
region=us-west-2
output=json

[profile corp-id]
source_profile=corp-id-base
mfa_serial=arn:aws:iam::123456789012:mfa/alice
role_arn=arn:aws:iam::123456789012:role/admin
region=us-west-2
output=json
```

#### MFA Management

This tool will help create and enable a virtual MFA device. The interface for the MFA device is a QR code
which will be shown to the user during setup. This QR code can be used with a password manager to provide the
One Time Passwords (OTP) values asked for in the script.

In the case where the user has a virtual MFA device already set up they can choose not to provision a new one.
This is done by issuing the `--no-mfa` flag on the command line in conjunction with the regular command from
above.

### setup-new-aws-user add-profile

Before running this tool, you will need to following pieces of information

- IAM role name - This is the IAM Role with permissions allowing access to AWS APIs
  and services. This is usually something like `admin` or `engineer`. Use the flag
  `--iam-role` with this value.
- AWS Region - This utility will default to "us-west-2" so if you are using this tool for GovCloud or other partitions you will need to provide a region specific to that partition.
- AWS profile - This is the name of the profile in your `~/.aws/config` profile
  that you wish to use as the basis for adding new profiles. The `source_profile`
  and `mfa_serial` is pulled from this profile.
  Use the flag name `--aws-profile` with this value.
- AWS Profiles and Account IDs - This is the set of aws profile names you wish to
  add along with the corresponding AWS account ID. They are referenced as
  `<AWS_PROFILE>:<AWS_ACCOUNT_ID>`. Use the flag name `--aws-profile-account`
  with each set you wish to add.

1. Run the setup-new-user script -

   ```sh
   setup-new-aws-user add-profile \
     --aws-profile <AWS_PROFILE> \
     --iam-role <IAM_ROLE> \
     --aws-region <AWS_REGION> \
     --aws-profile-account <AWS_PROFILE1>:<AWS_ACCOUNT_ID1> \
     --aws-profile-account <AWS_PROFILE2>:<AWS_ACCOUNT_ID2>
   ```

2. Once the tool has completed, you should be able to access the AWS account. You can run the following command filling in the `AWS_PROFILE` value

   ```sh
   aws-vault exec $AWS_PROFILE -- aws sts get-session
   ```

#### How `add-profile` modifies your ~/.aws/config

While your AWS access keys are stored in a password protected keychain managed by `aws-vault`, the configuration for
how you should access AWS accounts lives in ~/.aws/config. The `setup-new-aws-user add-profile` tool creates new profiles in
`~/.aws/config`. New profiles reference the `source_profile` and `mfa_serial` of the `--aws-profile` used in
the command and uses the IAM role granting you elevated access to the AWS account. Typically these IAM roles are
named `admin` or `engineer` and only uses temporary credentials leveraging AWS's Security Token Service (STS).
Below is an example config generated from this tool. Additional profiles will be similarly added and reference the
base profile.

```ini
[profile corp-new]
source_profile=corp-id-base
mfa_serial=arn:aws:iam::123456789012:mfa/alice
role_arn=arn:aws:iam::123456789012:role/engineer
region=us-west-2
output=json
```

**NOTE:** If you supply an aws-profile name that already exists in '~/.aws/config` this script will rewrite
that profile in your config.

### setup-new-aws-user version

To get the version of the tool run:

```sh
setup-new-aws-user version
```

In development mode you may see the word `development` returned. Otherwise you should see the version of the tool
as it was built by the release pipeline.

## Development setup

1. First, install these packages: `brew install pre-commit direnv go`
2. Next, clone the project repository.
3. Finally, run these commands inside the local repo: `direnv allow`
4. The `.envrc` will be loaded if `direnv` is installed.

### Testing

#### Unit Tests

Run pre-commit and Go tests

```shell
pre-commit run -a
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
go run ./cmd setup --iam-role engineer --iam-user testuser --aws-profile-account test-profile-name:123456789012
```

After running the script, try a command to ensure the new profile works as
expected:

Example (include AWS_VAULT_KEYCHAIN_NAME if the environment variable is not
set):

```shell
AWS_VAULT_KEYCHAIN_NAME=login aws-vault exec test-profile-name -- aws sts get-caller-identity
```

### Troubleshooting

#### User partially creates MFA device

The user might find themselves in an odd situation where the virtual MFA device was created but not assigned to the
user. This will prevent the user from coming back to the setup script and completing it. Here are steps to resolve if
the vMFA was created with no assigned user:

```sh
aws iam list-virtual-mfa-devices
# Find device with serial format of `arn:aws:iam::<AWS_ACCOUNT_ID>:mfa/<IAM_USERNAME>`
# It may be listed without a User associated with it.
SERIAL=arn:aws:iam::<AWS_ACCOUNT_ID>:mfa/<IAM_USERNAME>
aws iam delete-virtual-mfa-device --serial-number "$SERIAL"
```

If the device was registered to a user it may need to be deactivated first, in which case its easier to find the
`SERIAL` programatically:

```sh
export USERNAME=somebody
SERIAL=$(aws iam list-mfa-devices --user-name "${USERNAME}" | jq -r ".MFADevices[].SerialNumber")
aws iam deactivate-mfa-device --user-name "${USERNAME}" --serial-number "${SERIAL}"
aws iam delete-virtual-mfa-device --serial-number "$SERIAL"
```

Now the device should be completely removed. Have them re-run the script.

#### Publishing a release to Homebrew

This application is published to Homebrew and is done so via [goreleaser](https://goreleaser.com/) with the configuration defined in `.goreleaser.yml` and the `.github/workflows/release-macos.yml` GitHub Action that runs when a tag is created. To get the specifics of how this works, you can see the doc written [here](https://playbook.truss.dev/docs/developing/command-line-tools/HOW2GORELEASER). _hint_ Check 1password for Truss Infra GitHub credentials and a token attached. That's `GH_TOKEN` defined in the action.
