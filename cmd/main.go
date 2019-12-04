package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/jessevdk/go-flags"
	"github.com/skip2/go-qrcode"
	"gopkg.in/go-playground/validator.v9"
)

const maxNumAccessKeys = 2
const maxMFATokenPromptAttempts = 5

var validate *validator.Validate

// MFATokenPair holds two MFA tokens for enabling virtual
// MFA device
type MFATokenPair struct {
	Token1 string `validate:"numeric,len=6"`
	Token2 string `validate:"numeric,len=6,nefield=Token1"`
}

type cliOptions struct {
	AwsRegion      string `env:"AWS_REGION" long:"region" default:"us-west-2" description:"The AWS region"`
	AwsAccountID   int    `required:"true" env:"AWS_ACCOUNT_ID" long:"account-id" description:"The AWS account number"`
	AwsProfile     string `required:"true" env:"AWS_PROFILE" long:"profile" description:"The AWS profile name"`
	AwsIDProfile   string `env:"AWS_ID_PROFILE" long:"id-profile" description:"The AWS ID profile name"`
	AwsRootProfile string `env:"AWS_ROOT_PROFILE" long:"root-profile" description:"The AWS root profile name"`
	IAMUser        string `required:"true" long:"iam-user" description:"The IAM user name"`
	Role           string `required:"true" long:"role" description:"The user role type"`
	Output         string `long:"output" default:"json" description:"The AWS CLI output format"`
}

// User holds information for the AWS user being configured by this script
type User struct {
	Name            string
	Profile         *vault.Profile
	AccessKeyID     string
	SecretAccessKey string
}

// PromptAccessCredentials prompts the user for their AWS access key ID and
// secret access key, and sets the corresponding environment variables.
func (u *User) PromptAccessCredentials() error {
	accessKeyID, err := prompt.TerminalPrompt("Enter Access Key ID: ")
	if err != nil {
		return fmt.Errorf("error retrieving access key ID: %w", err)
	}

	secretKey, err := prompt.TerminalPrompt("Enter Secret Access Key: ")
	if err != nil {
		return fmt.Errorf("error retrieving secret access key: %w", err)
	}

	u.AccessKeyID = accessKeyID
	u.SecretAccessKey = secretKey

	err = SetCredentialEnvironmentVariables(accessKeyID, secretKey)
	if err != nil {
		return fmt.Errorf("unable to set credential environment variables: %w", err)
	}

	return nil
}

func (u *User) newIAMServiceSession() *iam.IAM {
	log.Println("Create IAM service session")
	sessionOpts := session.Options{
		Config: aws.Config{
			// Why aws.String(): https://github.com/aws/aws-sdk-go/issues/363
			Region:                        aws.String(u.Profile.Region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
	}
	sess, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		log.Fatalf("unable to create new session: %s", err)
	}
	return iam.New(sess)
}

// CreateVirtualMFADevice creates the user's virtual MFA device and updates the
// MFA serial in the profile field.
func (u *User) CreateVirtualMFADevice() error {
	log.Println("Creating the virtual MFA device...")

	svc := u.newIAMServiceSession()

	mfaDeviceInput := &iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: aws.String(u.Name),
	}

	mfaDeviceOutput, err := svc.CreateVirtualMFADevice(mfaDeviceInput)
	if err != nil {
		return fmt.Errorf("unable to create virtual mfa: %w", err)
	}

	u.Profile.MFASerial = *mfaDeviceOutput.VirtualMFADevice.SerialNumber

	// For the QR code, create a string that encodes:
	// otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String
	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
	content := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s",
		*mfaDeviceInput.VirtualMFADeviceName,
		u.Profile.Name,
		mfaDeviceOutput.VirtualMFADevice.Base32StringSeed,
	)

	err = PrintQRCode(content)
	if err != nil {
		return fmt.Errorf("unable to print qr code: %w", err)
	}

	return nil
}

func promptMFAtoken(message string) string {
	var token string
	for attempts := maxMFATokenPromptAttempts; token == "" && attempts > 0; attempts-- {
		t, err := prompt.TerminalPrompt(fmt.Sprintf("%s MFA token (%d attempts remaining): ", message, attempts))
		if err != nil {
			log.Println(err)
			continue
		}
		err = validate.Var(t, "numeric,len=6")
		if err != nil {
			fmt.Println("MFA token must be 6 digits. Please try again.")
			continue
		}
		token = t
	}
	return token
}

func getMFATokenPair() MFATokenPair {
	var mfaTokenPair MFATokenPair
	for attempts := maxMFATokenPromptAttempts; attempts > 0; attempts-- {
		fmt.Printf("Two unique MFA tokens needed to activate MFA device (%d attempts remaining)\n", attempts)
		authToken1 := promptMFAtoken("First")
		authToken2 := promptMFAtoken("Second")

		mfaTokenPair = MFATokenPair{
			Token1: authToken1,
			Token2: authToken2,
		}
		err := validate.Struct(mfaTokenPair)
		if err != nil {
			log.Println(err)
		} else {
			break
		}
	}
	return mfaTokenPair
}

// EnableVirtualMFADevice enables the user's MFA device
func (u *User) EnableVirtualMFADevice() error {
	log.Println("Enabling the virtual mfa device")
	if u.Profile.MFASerial == "" {
		return fmt.Errorf("profile mfa serial must be set")
	}

	mfaTokenPair := getMFATokenPair()

	svc := u.newIAMServiceSession()

	enableMFADeviceInput := &iam.EnableMFADeviceInput{
		AuthenticationCode1: aws.String(mfaTokenPair.Token1),
		AuthenticationCode2: aws.String(mfaTokenPair.Token2),
		SerialNumber:        aws.String(u.Profile.MFASerial),
		UserName:            aws.String(u.Name),
	}

	_, err := svc.EnableMFADevice(enableMFADeviceInput)
	if err != nil {
		return fmt.Errorf("unable to enable mfa device: %w", err)
	}

	return nil
}

// RotateAccessKeys rotates the user's AWS access key.
func (u *User) RotateAccessKeys(config *vault.Config) error {
	log.Println("Rotating AWS access keys")

	err := SetCredentialEnvironmentVariables(u.AccessKeyID, u.SecretAccessKey)
	if err != nil {
		return fmt.Errorf("unable to set environment variables: %w", err)
	}

	svc := u.newIAMServiceSession()

	listAccessKeysOutput, err := svc.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(u.Name),
	})
	if err != nil {
		return fmt.Errorf("unable to list access keys: %w", err)
	}

	if len(listAccessKeysOutput.AccessKeyMetadata) == maxNumAccessKeys {
		return fmt.Errorf("maximum of %v access keys have already been created for %s; delete your unused access key through the AWS console before trying again", maxNumAccessKeys, u.Name)
	}

	oldAccessKeyID := listAccessKeysOutput.AccessKeyMetadata[0].AccessKeyId

	log.Println("Creating new access key")
	newAccessKey, err := svc.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: aws.String(u.Name),
	})
	if err != nil {
		return fmt.Errorf("unable to create new access key: %w", err)
	}

	newAccessKeyID := newAccessKey.AccessKey.AccessKeyId
	newSecretAccessKey := newAccessKey.AccessKey.SecretAccessKey

	err = SetCredentialEnvironmentVariables(*newAccessKeyID, *newSecretAccessKey)
	if err != nil {
		return fmt.Errorf("unable to set enviroment variables with new credentials: %w", err)
	}

	err = AddAWSVaultProfile(u.Profile.Name, config)
	if err != nil {
		return fmt.Errorf("unable to add new credentials to aws-vault profile: %w", err)
	}

	// Add a delay to allow the new IAM credentials to propagate.
	// TODO: replace this with a retry similar to https://github.com/99designs/aws-vault/blob/08380e6561cc885491717ed2dce164ea6076c438/vault/rotator.go#L197
	log.Println("Sleeping....")
	time.Sleep(30 * time.Second)

	svc = u.newIAMServiceSession()

	log.Println("Deleting old access key")
	_, err = svc.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: oldAccessKeyID,
		UserName:    aws.String(u.Name),
	})
	if err != nil {
		return fmt.Errorf("unable to delete old access key: %w", err)
	}

	return nil
}

// AddAWSVaultProfile uses aws-vault to store AWS credentials for the given
// profile. The function assumes the AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY environment variable are already populated with the
// user's credentials.
func AddAWSVaultProfile(profile string, awsConfig *vault.Config) error {
	log.Println("Adding profile to aws-vault")
	var accessKeyID, secretKey string

	if accessKeyID = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyID == "" {
		return fmt.Errorf("Missing value for AWS_ACCESS_KEY_ID")
	}
	if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
		return fmt.Errorf("Missing value for AWS_SECRET_ACCESS_KEY")
	}

	keyring, err := getKeyRing()
	if err != nil {
		return fmt.Errorf("unable to get keyring: %w", err)
	}

	creds := credentials.Value{AccessKeyID: accessKeyID, SecretAccessKey: secretKey}
	provider := &vault.KeyringProvider{Keyring: *keyring, Profile: profile}

	if err := provider.Store(creds); err != nil {
		return fmt.Errorf("unable to store credentials: %w", err)
	}

	log.Printf("Added credentials to profile %q in vault\n", profile)

	err = deleteSession(profile, awsConfig, keyring)
	if err != nil {
		return fmt.Errorf("unable to delete session: %w", err)
	}

	return nil
}

// RemoveAWSVaultSession removes the aws-vault session for the given profile
func RemoveAWSVaultSession(profile string, awsConfig *vault.Config) error {
	log.Printf("Removing aws-vault session")

	keyring, err := getKeyRing()
	if err != nil {
		return fmt.Errorf("unable to get keyring: %w", err)
	}

	err = deleteSession(profile, awsConfig, keyring)
	if err != nil {
		return fmt.Errorf("unable to delete session: %w", err)
	}

	return nil
}

func getKeyRing() (*keyring.Keyring, error) {
	keychainName := os.Getenv("AWS_VAULT_KEYCHAIN_NAME")
	if keychainName == "" {
		keychainName = "login"
	}

	ring, err := keyring.Open(keyring.Config{
		ServiceName:              "aws-vault",
		AllowedBackends:          []keyring.BackendType{keyring.KeychainBackend},
		KeychainName:             keychainName,
		KeychainTrustApplication: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error opening keyring: %w", err)
	}

	return &ring, nil
}

func deleteSession(profile string, awsConfig *vault.Config, keyring *keyring.Keyring) error {
	sessions, err := vault.NewKeyringSessions(*keyring, awsConfig)
	if err != nil {
		return fmt.Errorf("unable to create new keyring session: %w", err)
	}

	if n, _ := sessions.Delete(profile); n > 0 {
		log.Printf("Deleted %d existing sessions.\n", n)
	}

	return nil
}

// SetCredentialEnvironmentVariables updates the AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY environment variables.
func SetCredentialEnvironmentVariables(accessKeyID, secretKey string) error {
	log.Println("Setting AWS credential environment variables")

	err := os.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)
	if err != nil {
		return err
	}

	err = os.Setenv("AWS_SECRET_ACCESS_KEY", secretKey)
	if err != nil {
		return err
	}

	return nil
}

// UnsetCredentialEnvironmentVariables unsets the AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY environment variables.
func UnsetCredentialEnvironmentVariables() error {
	log.Println("Unsetting AWS credential environment variables")
	err := os.Unsetenv("AWS_ACCESS_KEY_ID")
	if err != nil {
		return err
	}

	err = os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	if err != nil {
		return err
	}

	return nil
}

// PrintQRCode prints the payload string as a QR code to the terminal
func PrintQRCode(payload string) error {
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("unable to create qr code: %w", err)
	}
	fmt.Println(q.ToSmallString(false))
	return nil
}

func main() {
	// parse command line flags
	var options cliOptions
	parser := flags.NewParser(&options, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatal(err)
	}

	validate = validator.New()

	// initialize things
	profile := vault.Profile{
		Name: options.AwsProfile,
		RoleARN: fmt.Sprintf("arn:aws:iam::%v:role/%v",
			options.AwsAccountID, options.Role),
		Region: options.AwsRegion,
	}

	user := User{
		Name:    options.IAMUser,
		Profile: &profile,
	}

	config, err := vault.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Checking whether profile exists in AWS config file")
	_, exists := config.Profile(profile.Name)
	if exists {
		log.Fatalf("Profile already exists in AWS config file: %s", profile.Name)
	}

	err = user.PromptAccessCredentials()
	if err != nil {
		log.Fatal(err)
	}

	err = AddAWSVaultProfile(profile.Name, config)
	if err != nil {
		log.Fatal(err)
	}

	err = user.CreateVirtualMFADevice()
	if err != nil {
		log.Fatal(err)
	}

	err = user.EnableVirtualMFADevice()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Updating the AWS config file")
	err = config.Add(profile)
	if err != nil {
		log.Fatal(err)
	}

	err = UnsetCredentialEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}

	err = RemoveAWSVaultSession(profile.Name, config)
	if err != nil {
		log.Fatal(err)
	}

	err = user.RotateAccessKeys(config)
	if err != nil {
		log.Fatal(err)
	}

	// If we got this far, we win
	log.Println("Victory!")
}
