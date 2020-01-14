package main

import (
	"fmt"
	"log"
	"os"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jessevdk/go-flags"
	"github.com/skip2/go-qrcode"
	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/ini.v1"
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
	AwsRegion    string `env:"AWS_REGION" long:"region" default:"us-west-2" description:"The AWS region"`
	AwsAccountID int    `required:"true" env:"AWS_ACCOUNT_ID" long:"account-id" description:"The AWS account number"`
	AwsProfile   string `required:"true" env:"AWS_PROFILE" long:"profile" description:"The AWS profile name"`
	IAMUser      string `required:"true" long:"iam-user" description:"The IAM user name"`
	Role         string `required:"true" long:"role" description:"The user role type"`
	Output       string `long:"output" default:"json" description:"The AWS CLI output format"`
}

// User holds information for the AWS user being configured by this script
type User struct {
	Name            string
	Profile         *vault.Profile
	Output          string
	Config          *vault.Config
	AccessKeyID     string
	SecretAccessKey string
}

// Setup orchestrates the tasks to create the user's MFA and rotate access
// keys.
func (u *User) Setup() {
	err := u.PromptAccessCredentials()
	if err != nil {
		log.Fatal(err)
	}

	err = u.AddVaultProfile()
	if err != nil {
		log.Fatal(err)
	}

	err = u.CreateVirtualMFADevice()
	if err != nil {
		log.Fatal(err)
	}

	err = u.EnableVirtualMFADevice()
	if err != nil {
		log.Fatal(err)
	}

	err = u.UpdateAWSConfigFile()
	if err != nil {
		log.Fatal(err)
	}

	err = u.RemoveVaultSession()
	if err != nil {
		log.Fatal(err)
	}

	err = u.RotateAccessKeys()
	if err != nil {
		log.Fatal(err)
	}

}

// PromptAccessCredentials prompts the user for their AWS access key ID and
// secret access key.
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

	return nil
}

func (u *User) newSession() (*session.Session, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: credentials.NewStaticCredentialsFromCreds(credentials.Value{
				AccessKeyID:     u.AccessKeyID,
				SecretAccessKey: u.SecretAccessKey,
			}),
			Region: aws.String(u.Profile.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %w", err)
	}
	return sess, nil
}

func (u *User) newMFASession() (*session.Session, error) {
	mfaToken := promptMFAtoken("")
	basicSession, err := u.newSession()
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %w", err)
	}
	stsClient := sts.New(basicSession)
	getSessionTokenOutput, err := stsClient.GetSessionToken(&sts.GetSessionTokenInput{
		SerialNumber: aws.String(u.Profile.MFASerial),
		TokenCode:    aws.String(mfaToken),
	})
	if err != nil {
		log.Fatalf("unable to get session token: %v", err)
	}
	mfaSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: credentials.NewStaticCredentialsFromCreds(credentials.Value{
				AccessKeyID:     *getSessionTokenOutput.Credentials.AccessKeyId,
				SecretAccessKey: *getSessionTokenOutput.Credentials.SecretAccessKey,
				SessionToken:    *getSessionTokenOutput.Credentials.SessionToken,
			}),
			Region: aws.String(u.Profile.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get mfa session: %w", err)
	}
	return mfaSession, nil
}

// CreateVirtualMFADevice creates the user's virtual MFA device and updates the
// MFA serial in the profile field.
func (u *User) CreateVirtualMFADevice() error {
	log.Println("Creating the virtual MFA device...")

	sess, err := u.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

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

	err = printQRCode(content)
	if err != nil {
		return fmt.Errorf("unable to print qr code: %w", err)
	}

	return nil
}

func promptMFAtoken(messagePrefix string) string {
	var token string
	for attempts := maxMFATokenPromptAttempts; token == "" && attempts > 0; attempts-- {
		t, err := prompt.TerminalPrompt(fmt.Sprintf("%sMFA token (%d attempts remaining): ", messagePrefix, attempts))
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
		authToken1 := promptMFAtoken("First ")
		authToken2 := promptMFAtoken("Second ")

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

	sess, err := u.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

	enableMFADeviceInput := &iam.EnableMFADeviceInput{
		AuthenticationCode1: aws.String(mfaTokenPair.Token1),
		AuthenticationCode2: aws.String(mfaTokenPair.Token2),
		SerialNumber:        aws.String(u.Profile.MFASerial),
		UserName:            aws.String(u.Name),
	}

	_, err = svc.EnableMFADevice(enableMFADeviceInput)
	if err != nil {
		return fmt.Errorf("unable to enable mfa device: %w", err)
	}

	return nil
}

// RotateAccessKeys rotates the user's AWS access key.
func (u *User) RotateAccessKeys() error {
	log.Println("Rotating AWS access keys")

	sess, err := u.newMFASession()
	if err != nil {
		return fmt.Errorf("unable to get mfa session: %w", err)
	}
	iamClient := iam.New(sess)
	listAccessKeysOutput, err := iamClient.ListAccessKeys(&iam.ListAccessKeysInput{
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
	newAccessKey, err := iamClient.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: aws.String(u.Name),
	})
	if err != nil {
		return fmt.Errorf("unable to create new access key: %w", err)
	}

	u.AccessKeyID = *newAccessKey.AccessKey.AccessKeyId
	u.SecretAccessKey = *newAccessKey.AccessKey.SecretAccessKey

	err = u.AddVaultProfile()
	if err != nil {
		return fmt.Errorf("unable to add new credentials to aws-vault profile: %w", err)
	}

	log.Println("Deleting old access key")
	_, err = iamClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: oldAccessKeyID,
		UserName:    aws.String(u.Name),
	})

	if err != nil {
		return fmt.Errorf("unable to delete old access key: %w", err)
	}

	return nil
}

// AddVaultProfile uses aws-vault to store AWS credentials for the user's
// profile.
func (u *User) AddVaultProfile() error {
	keyring, err := getKeyRing()
	if err != nil {
		return fmt.Errorf("unable to get keyring: %w", err)
	}

	creds := credentials.Value{AccessKeyID: u.AccessKeyID, SecretAccessKey: u.SecretAccessKey}
	provider := &vault.KeyringProvider{Keyring: *keyring, Profile: u.Profile.Name}

	if err := provider.Store(creds); err != nil {
		return fmt.Errorf("unable to store credentials: %w", err)
	}

	log.Printf("Added credentials to profile %q in vault\n", u.Profile.Name)

	err = deleteSession(u.Profile.Name, u.Config, keyring)
	if err != nil {
		return fmt.Errorf("unable to delete session: %w", err)
	}

	return nil
}

// UpdateAWSConfigFile adds the user's AWS profile to the AWS config file
func (u *User) UpdateAWSConfigFile() error {
	log.Println("Updating the AWS config file")
	// get path to aws config file
	awsCfgPath, err := vault.ConfigPath()
	if err != nil {
		return fmt.Errorf("unable to get aws config file path: %w", err)
	}
	// load the ini file
	iniFile, err := ini.Load(awsCfgPath)
	if err != nil {
		return fmt.Errorf("unable to load aws config file: %w", err)
	}
	// add the profile
	sectionName := fmt.Sprintf("profile %s", u.Profile.Name)
	section, err := iniFile.NewSection(sectionName)
	if err != nil {
		return fmt.Errorf("error creating section %q: %w", u.Profile.Name, err)
	}
	if err = section.ReflectFrom(&u.Profile); err != nil {
		return fmt.Errorf("error mapping profile to ini file: %w", err)
	}
	_, err = section.NewKey("output", u.Output)
	if err != nil {
		return fmt.Errorf("unable to add output key: %w", err)
	}
	// save it back to the aws config path
	return iniFile.SaveTo(awsCfgPath)
}

// RemoveVaultSession removes the aws-vault session for the profile.
func (u *User) RemoveVaultSession() error {
	log.Printf("Removing aws-vault session")

	keyring, err := getKeyRing()
	if err != nil {
		return fmt.Errorf("unable to get keyring: %w", err)
	}

	err = deleteSession(u.Profile.Name, u.Config, keyring)
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

func printQRCode(payload string) error {
	q, err := qrcode.New(payload, qrcode.Low)
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

	config, err := vault.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Checking whether profile exists in AWS config file")
	_, exists := config.Profile(profile.Name)
	if exists {
		log.Fatalf("Profile already exists in AWS config file: %s", profile.Name)
	}

	user := User{
		Name:    options.IAMUser,
		Profile: &profile,
		Output:  options.Output,
		Config:  config,
	}

	user.Setup()

	// If we got this far, we win
	log.Println("Victory!")
}
