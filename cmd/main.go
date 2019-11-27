package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/jessevdk/go-flags"
	"github.com/skip2/go-qrcode"
)

type cliOptions struct {
	AwsRegion      string `env:"AWS_REGION" long:"region" default:"us-west-2" description:"region"`
	AwsAccountID   int    `required:"true" env:"AWS_ACCOUNT_ID" long:"account_id" description:"account id"`
	AwsProfile     string `required:"true" env:"AWS_PROFILE" long:"profile" description:"profile name"`
	AwsIDProfile   string `required:"true" env:"AWS_ID_PROFILE" long:"id_profile" description:"id profile name"`
	AwsRootProfile string `env:"AWS_ROOT_PROFILE" long:"root_profile" description:"root profile name"`
	IAMUser        string `required:"true" env:"" long:"iam_user" description:"iam user name"`
	Role           string `required:"true" long:"role" choice:"admin-org-root" choice:"engineer" choice:"admin" description:"user role type"`
	Output         string `long:"output" default:"json" description:"aws-cli output format"`
}

func (c *cliOptions) validateProfileVars() error {
	log.Println("Validating profile variables")
	if c.AwsProfile != c.AwsRootProfile && c.AwsProfile != c.AwsIDProfile {
		return fmt.Errorf("found AWS_PROFILE=%q, expecting AWS_PROFILE to match AWS_ROOT_PROFILE (%q) or AWS_ID_PROFILE (%q); there are no users in other accounts, just roles",
			c.AwsProfile,
			c.AwsRootProfile,
			c.AwsIDProfile,
		)
	}
	return nil
}

// User holds information for the AWS user being configured by this script
type User struct {
	Name string
}

// MFAManager handles the MFA setup for a user
type MFAManager struct {
	Service *iam.IAM
	User    *User
	Profile *vault.Profile
}

// CreateServiceSession initializes an IAM service session for a user. Set
// the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables with
// the user's temporary credentials before invoking this method.
func (m *MFAManager) CreateServiceSession() error {
	log.Println("Create IAM service session")
	sessionOpts := session.Options{
		Config: aws.Config{
			// Why aws.String(): https://github.com/aws/aws-sdk-go/issues/363
			Region:                        aws.String(m.Profile.Region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
	}
	sess, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		return fmt.Errorf("unable to create new session: %w", err)
	}
	m.Service = iam.New(sess)
	return nil
}

// CreateVirtualMFADevice creates the user's virtual MFA device and updates the
// MFA serial in the profile field.
func (m *MFAManager) CreateVirtualMFADevice() error {
	log.Println("Creating the virtual MFA device...")

	mfaDeviceInput := &iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: aws.String(m.User.Name),
	}

	mfaDeviceOutput, err := m.Service.CreateVirtualMFADevice(mfaDeviceInput)
	if err != nil {
		return fmt.Errorf("unable to create virtual mfa: %w", err)
	}

	m.Profile.MFASerial = *mfaDeviceOutput.VirtualMFADevice.SerialNumber

	// For the QR code, create a string that encodes:
	// otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String
	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
	content := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s",
		*mfaDeviceInput.VirtualMFADeviceName,
		m.Profile.Name,
		mfaDeviceOutput.VirtualMFADevice.Base32StringSeed,
	)

	err = m.PrintQRCode(content)
	if err != nil {
		return fmt.Errorf("unable to print qr code: %w", err)
	}

	return nil
}

// PrintQRCode prints the payload string as a QR code to the terminal
func (m *MFAManager) PrintQRCode(payload string) error {
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("unable to create qr code: %w", err)
	}
	fmt.Println(q.ToSmallString(false))
	return nil
}

// EnableVirtualMFADevice enables the user's MFA device
func (m *MFAManager) EnableVirtualMFADevice() error {
	log.Println("Enabling the virtual mfa device")
	if m.Profile.MFASerial == "" {
		return fmt.Errorf("profile mfa serial must be set")
	}
	// TODO:
	// - Validate that the tokens are 6 character integers & store them so they
	//   can't be reused
	// - Check that the device is correct by polling ListVirtualMFADevices with
	//   assignment status "Assigned"
	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.EnableVirtualMFADevice
	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.ListVirtualMFADevices

	authToken1, err := prompt.TerminalPrompt("First MFA token: ")
	if err != nil {
		return fmt.Errorf("unable to read token: %w", err)
	}
	authToken2, err := prompt.TerminalPrompt("Second MFA token: ")
	if err != nil {
		return fmt.Errorf("unable to read token: %w", err)
	}
	enableMFADeviceInput := &iam.EnableMFADeviceInput{
		AuthenticationCode1: aws.String(authToken1),
		AuthenticationCode2: aws.String(authToken2),
		SerialNumber:        aws.String(m.Profile.MFASerial),
		UserName:            aws.String(m.User.Name),
	}

	_, err = m.Service.EnableMFADevice(enableMFADeviceInput)
	if err != nil {
		return fmt.Errorf("unable to enable mfa device: %w", err)
	}

	return nil
}

// AddAWSVaultProfile uses aws-vault to store AWS credentials for the given
// profile. The function assumes the AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY environment variable are already populated with the
// user's temporary credentials.
func AddAWSVaultProfile(profile string, awsConfig *vault.Config) error {
	log.Println("Adding profile to AWS vault")
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

	sessions, err := vault.NewKeyringSessions(*keyring, awsConfig)
	if err != nil {
		return fmt.Errorf("unable to create new keyring session: %w", err)
	}

	if n, _ := sessions.Delete(profile); n > 0 {
		fmt.Printf("Deleted %d existing sessions.\n", n)
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

// SetCredentialEnvironmentVariables prompts the user for their temporary AWS
// credentials and updates the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
// environment variables.
func SetCredentialEnvironmentVariables() error {
	log.Println("Setting AWS credential environment variables")
	accessKeyID, err := prompt.TerminalPrompt("Enter Access Key ID: ")
	if err != nil {
		return fmt.Errorf("error retrieving access key ID: %w", err)
	}

	err = os.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)
	if err != nil {
		return err
	}

	secretKey, err := prompt.TerminalPrompt("Enter Secret Access Key: ")
	if err != nil {
		return fmt.Errorf("error retrieving secret access key: %w", err)
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

func rotateKeys() error {
	log.Printf("Making subprocess call to rotate-aws-access-key")

	// TODO: I'm not sure exec.Command() supports subprocess interaction with the user
	cmd := exec.Command("echo", "This would run rotate-aws-access-key") // TODO: use the real command

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	slurp, _ := ioutil.ReadAll(stdout)
	fmt.Printf("%s", slurp)

	return nil
}

// func removeAWSVaultSession() error {
// 	log.Printf("Making subprocess call to aws-vault remove")
// 	cmd := exec.Command("aws-vault", "remove", os.Getenv("AWS_PROFILE"), "--sessions-only")

// 	stdout, err := cmd.StdoutPipe()
// 	if err != nil {
// 		return err
// 	}
// 	if err := cmd.Start(); err != nil {
// 		return err
// 	}

// 	slurp, _ := ioutil.ReadAll(stdout)
// 	fmt.Printf("%s", slurp)

// 	return nil
// }

func main() {
	// parse command line flags
	var options cliOptions
	parser := flags.NewParser(&options, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatal(err)
	}
	err = options.validateProfileVars()
	if err != nil {
		log.Fatal(err)
	}

	// initialize things
	user := User{
		Name: options.IAMUser,
	}

	profile := vault.Profile{
		Name: options.AwsProfile,
		RoleARN: fmt.Sprintf("arn:aws:iam::%v:role/%v",
			options.AwsAccountID, options.Role),
		Region: options.AwsRegion,
	}

	mfaManager := MFAManager{
		User:    &user,
		Profile: &profile,
	}

	config, err := vault.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Checking whether profile exists in aws config file")
	_, exists := config.Profile(profile.Name)
	if exists {
		log.Fatalf("Profile already exists in aws config file: %s", profile.Name)
	}

	err = SetCredentialEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}

	err = AddAWSVaultProfile(profile.Name, config)
	if err != nil {
		log.Fatal(err)
	}

	err = mfaManager.CreateServiceSession()
	if err != nil {
		log.Fatal(err)
	}

	err = mfaManager.CreateVirtualMFADevice()
	if err != nil {
		log.Fatal(err)
	}

	err = mfaManager.EnableVirtualMFADevice()
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

	// removeAWSVaultSession()

	log.Println("Rotating out the temporary AWS access keys...")

	err = rotateKeys()
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Success!")
	}

	// If we got this far, we win
	log.Println("Victory!")
}
