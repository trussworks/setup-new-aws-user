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
	IAMUser   string
	Role      string
	MFASerial string
	// AccessKeyID     string
	// SecretAccessKey string
}

// func (u *User) SetCredentialEnvironmentVariables() error {
// 	accessKeyID, err := prompt.TerminalPrompt("Enter Access Key ID: ")
// 	if err != nil {
// 		return fmt.Errorf("error retrieving access key ID")
// 	}
// 	u.AccessKeyID = accessKeyID

// 	secretKey, err := prompt.TerminalPrompt("Enter Secret Access Key: ")
// 	if err != nil {
// 		return fmt.Errorf("error retrieving secret access key")
// 	}
// 	u.SecretAccessKey = secretKey

// 	return nil
// }

// type AWSConfigManager struct {
// 	Config *vault.Config
// }

// func (m *AWSConfigManager) Exists(profile string) bool {
// 	log.Println("Checking if profile already exists in aws config file")
// 	_, exists := m.Config.Profile(profile)
// 	return exists
// }

// func (m *AWSConfigManager) Add(profile vault.Profile) error {
// 	log.Println("Adding profile to aws config file")
// 	err := m.Config.Add(profile)
// 	if err != nil {
// 		return fmt.Errorf("unable to add profile: %w", err)
// 	}
// 	return nil
// }

// type AWSVaultManager struct {
// 	keyringImpl keyring.Keyring
// }

// func NewAWSVaultManager() (*AWSVaultManager, error) {

// func (c *AWSConfigManager) ValidateProfileVars() error {
// 	if c.AwsProfile != c.AwsRootProfile && c.AwsProfile != c.AwsIDProfile {
// 		return fmt.Errorf("found AWS_PROFILE=%q, expecting AWS_PROFILE to match AWS_ROOT_PROFILE (%q) or AWS_ID_PROFILE (%q); there are no users in other accounts, just roles",
// 			c.AwsProfile,
// 			c.AwsRootProfile,
// 			c.AwsIDProfile,
// 		)
// 	}
// 	return nil
// }

// MFAManager handles the MFA setup for a user
type MFAManager struct {
	Service *iam.IAM
	User    *User
	Profile *vault.Profile
	// MFASerial string
	// MFADevice *iam.VirtualMFADevice
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
		VirtualMFADeviceName: aws.String(m.User.IAMUser),
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
		UserName:            aws.String(m.User.IAMUser),
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
		ServiceName:     "aws-vault",
		AllowedBackends: []keyring.BackendType{keyring.KeychainBackend},
		KeychainName:    keychainName,
		// FileDir:                  "~/.awsvault/keys/",
		// FilePasswordFunc:         fileKeyringPassphrasePrompt,
		// PassDir:                  GlobalFlags.PassDir,
		// PassCmd:                  GlobalFlags.PassCmd,
		// PassPrefix:               GlobalFlags.PassPrefix,
		// LibSecretCollectionName:  "awsvault",
		// KWalletAppID:             "aws-vault",
		// KWalletFolder:            "aws-vault",
		KeychainTrustApplication: true,
		// WinCredPrefix:            "aws-vault",
	})
	if err != nil {
		return nil, fmt.Errorf("error opening keyring: %w", err)
	}

	// return &AWSVaultManager{keyringImpl: ring}, nil
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

// var (
// 	options cliOptions
// )

// func text2qr(payload string) {
// 	q, err := qrcode.New(payload, qrcode.Medium)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println(q.ToSmallString(false))
// }

// func checkAwsCfg() {
// 	log.Printf("Checking that the profile %q does not already exist in the aws-cli config", options.AwsProfile)

// 	awscfg := path.Join(os.Getenv("HOME"), ".aws", "config")
// 	cfg, err := ini.Load(awscfg)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	secs := cfg.Sections()

// 	for _, section := range secs {
// 		if section.Name() == fmt.Sprintf("profile %s", options.AwsProfile) {
// 			log.Fatalf("Profile %q already exists! If you want to replace it, delete the existing profile in your ~/.aws/config file.", options.AwsProfile)
// 		}
// 	}
// }

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

// func readLine(prompt string) (string, error) {
// 	// Prompt the user for input, and return the input
// 	reader := bufio.NewReader(os.Stdin)

// 	fmt.Print(prompt)

// 	input, err := reader.ReadString('\n')
// 	if err != nil {
// 		return input, err
// 	}

// 	input = strings.TrimSuffix(input, "\n")

// 	return input, nil
// }

// func getAccessKey() (string, string, error) {
// 	// Get temporary access keys from the user
// 	accessKeyID, err := readLine("Enter temporary AWS Access Key ID: ")
// 	if err != nil {
// 		return accessKeyID, "", err
// 	}

// 	accessKeySecret, err := readLine("Enter temporary AWS Secret Access Key: ")
// 	if err != nil {
// 		return accessKeyID, "", err
// 	}

// 	return accessKeyID, accessKeySecret, nil
// }

// func checkStsAccess(stsSvc *sts.STS) error {
// 	log.Println("Testing access to AWS...")

// 	input := &sts.GetCallerIdentityInput{}
// 	caller, err := stsSvc.GetCallerIdentity(input)
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("Caller: %v", *caller)

// 	return nil
// }

// func checkStsAccessV2() error {
// 	log.Println("Using aws-vault to check STS access")
// 	log.Printf("AWS_VAULT_KEYCHAIN_NAME: %s\n", os.Getenv("AWS_VAULT_KEYCHAIN_NAME"))
// 	//
// 	cmd := exec.Command("aws-vault", "exec", os.Getenv("AWS_PROFILE"), "--", "aws", "sts", "get-caller-identity")

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

// // Creates a virtual MFA device for the user specified in the AwsProfile
// // cli option. Returns mfaDeviceSerial, err
// func createVirtualMfaDevice(iamSvc *iam.IAM) (string, error) {
// 	mfaDeviceInput := &iam.CreateVirtualMFADeviceInput{
// 		VirtualMFADeviceName: aws.String(options.IAMUser),
// 	}

// 	mfaDeviceOutput, err := iamSvc.CreateVirtualMFADevice(mfaDeviceInput)
// 	if err != nil {
// 		return "", err
// 	}

// 	// For the QR code, create a string that encodes:
// 	// otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String
// 	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
// 	content := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s",
// 		*mfaDeviceInput.VirtualMFADeviceName,
// 		options.AwsProfile,
// 		mfaDeviceOutput.VirtualMFADevice.Base32StringSeed,
// 	)

// 	text2qr(content)

// 	return *mfaDeviceOutput.VirtualMFADevice.SerialNumber, nil
// }

// func enableVirtualMFADevice(iamSvc *iam.IAM, mfaSerial string) {
// 	// TODO:
// 	// - Validate that the tokens are 6 character integers & store them so they
// 	//   can't be reused
// 	// - Check that the device is correct by polling ListVirtualMFADevices with
// 	//   assignment status "Assigned"
// 	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.EnableVirtualMFADevice
// 	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.ListVirtualMFADevices

// 	// get two auth codes from user
// 	authToken1, err := readLine("First MFA token: ")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	authToken2, err := readLine("Second MFA token: ")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	enableMFADeviceInput := &iam.EnableMFADeviceInput{
// 		AuthenticationCode1: aws.String(authToken1),
// 		AuthenticationCode2: aws.String(authToken2),
// 		SerialNumber:        aws.String(mfaSerial),
// 		UserName:            aws.String(options.IAMUser),
// 	}

// 	_, err = iamSvc.EnableMFADevice(enableMFADeviceInput)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// TODO: test the MFA device
// }

// func configureAwsCliProfile(mfaArn string, profileArn string) error {
// 	configFile, err := vault.LoadConfigFromEnv()
// 	if err != nil {
// 		return err
// 	}

// 	profileSection := vault.Profile{
// 		Name:      options.AwsProfile,
// 		MFASerial: mfaArn,
// 		RoleARN:   profileArn,
// 		Region:    options.AwsRegion,
// 	}

// 	err = configFile.Add(profileSection)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

// func addAWSVaultProfile() {
// 	var accessKeyID, secretKey string

// 	input := cli.AddCommandInput{
// 		Profile: options.AwsProfile,

// 	}

// 	if source, _ := awsConfig.SourceProfile(input.Profile); source.Name != input.Profile {
// 		app.Fatalf("Your profile has a source_profile of %s, adding credentials to %s won't have any effect",
// 			source.Name, input.Profile)
// 		return
// 	}

// 	if input.FromEnv {
// 		if accessKeyId = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyId == "" {
// 			app.Fatalf("Missing value for AWS_ACCESS_KEY_ID")
// 			return
// 		}
// 		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
// 			app.Fatalf("Missing value for AWS_SECRET_ACCESS_KEY")
// 			return
// 		}
// 	} else {
// 		var err error
// 		if accessKeyId, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
// 			app.Fatalf(err.Error())
// 			return
// 		}
// 		if secretKey, err = prompt.TerminalPrompt("Enter Secret Access Key: "); err != nil {
// 			app.Fatalf(err.Error())
// 			return
// 		}
// 	}

// 	creds := credentials.Value{AccessKeyID: accessKeyId, SecretAccessKey: secretKey}
// 	provider := &vault.KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}

// 	if err := provider.Store(creds); err != nil {
// 		app.Fatalf(err.Error())
// 		return
// 	}

// 	fmt.Printf("Added credentials to profile %q in vault\n", input.Profile)

// 	sessions, err := vault.NewKeyringSessions(input.Keyring, awsConfig)
// 	if err != nil {
// 		app.Fatalf(err.Error())
// 		return
// 	}

// 	if n, _ := sessions.Delete(input.Profile); n > 0 {
// 		fmt.Printf("Deleted %d existing sessions.\n", n)
// 	}

// 	if _, hasProfile := awsConfig.Profile(input.Profile); !hasProfile {
// 		if input.AddConfig {
// 			// copy a source profile if one exists
// 			newProfileFromSource, _ := awsConfig.SourceProfile(input.Profile)
// 			newProfileFromSource.Name = input.Profile

// 			log.Printf("Adding profile %s to config at %s", input.Profile, awsConfig.Path)
// 			if err = awsConfig.Add(newProfileFromSource); err != nil {
// 				app.Fatalf("Error adding profile: %#v", err)
// 			}
// 		}
// 	}
// }

// func addAWSVaultProfile() error {
// 	log.Printf("Making subprocess call to aws-vault add")
// 	// log.Printf("AWS_ACCESS_KEY_ID: %s\n", os.Getenv("AWS_ACCESS_KEY_ID"))
// 	// log.Printf("AWS_SECRET_ACCESS_KEY: %s\n", os.Getenv("AWS_SECRET_ACCESS_KEY"))
// 	cmd := exec.Command("aws-vault", "add", "--env", os.Getenv("AWS_PROFILE"))

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
	// check aws profile environment variables
	err = options.validateProfileVars()
	if err != nil {
		log.Fatal(err)
	}

	// initialize things
	user := User{
		IAMUser: options.IAMUser,
		Role:    options.Role,
	}

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
	// configManager := AWSConfigManager{
	// 	Config: config,
	// }

	// * Verify that the profile does not exist in the AWS cli config
	// checkAwsCfg()
	// exists := configManager.Exists(profile.Name)
	log.Println("Checking whether profile exists in aws config file")
	_, exists := config.Profile(profile.Name)
	if exists {
		log.Fatalf("Profile already exists in aws config file: %s", profile.Name)
	}

	// * Get the user's temporary access credentials
	// accessKeyID, accessKeySecret, err := getAccessKey()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // AWS sdk will not read authentication crendentials as arguments to a
	// // function call. Since we don't want to use the aws-cli config at this
	// // point, we verify that the env vars are set
	// // os.Setenv("AWS_PROFILE", options.AwsProfile)
	// os.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)
	// os.Setenv("AWS_SECRET_ACCESS_KEY", accessKeySecret)

	err = SetCredentialEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}

	err = AddAWSVaultProfile(profile.Name, config)
	if err != nil {
		log.Fatal(err)
	}

	// // Create STS and IAM sessions
	// sessionOpts := session.Options{
	// 	Config: aws.Config{
	// 		// Why aws.String(): https://github.com/aws/aws-sdk-go/issues/363
	// 		Region:                        aws.String(options.AwsRegion),
	// 		CredentialsChainVerboseErrors: aws.Bool(true),
	// 	},
	// }
	// sess, err := session.NewSessionWithOptions(sessionOpts)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// // stsSvc := sts.New(sess)
	mfaManager := MFAManager{
		User:    &user,
		Profile: &profile,
	}
	// iamSvc := iam.New(sess)
	err = mfaManager.CreateServiceSession()
	if err != nil {
		log.Fatal(err)
	}

	// // * Verify access to AWS using the temporary credentials we have
	// log.Println("Checking STS access...")

	// err = checkStsAccess(stsSvc)
	// if err != nil {
	// 	log.Fatal(err)
	// } else {
	// 	log.Println("Success!")
	// }

	// * Create the virtual MFA device
	// log.Println("Creating the virtual MFA device...")

	// mfaSerial, err := createVirtualMfaDevice(iamSvc)
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

	// // enableVirtualMFADevice(iamSvc, mfaSerial)

	// // * Configure the AWS CLI profile
	// log.Println("Configuring aws-cli...")

	// getUserInput := &iam.GetUserInput{
	// 	UserName: aws.String(options.IAMUser),
	// }
	// _, err = iamSvc.GetUser(getUserInput)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// profileArn := fmt.Sprintf("arn:aws:iam::%v:role/%v",
	// 	options.AwsAccountID, options.Role)

	// err = configureAwsCliProfile(mfaSerial, profileArn)
	// if err != nil {
	// 	log.Fatal(err)
	// } else {
	// 	log.Println("Success!")
	// }

	// // * Verify access to AWS using the newly created MFA device & config file
	// //   We unset the environment variables to ensure the access keys are read
	// //   from the keyring
	// log.Println("Checking STS access...")
	// os.Unsetenv("AWS_ACCESS_KEY_ID")
	// os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	err = UnsetCredentialEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}

	// removeAWSVaultSession()

	// err = checkStsAccessV2()
	// if err != nil {
	// 	log.Fatal(err)
	// } else {
	// 	log.Println("Success!")
	// }

	// * Rotate AWS keys
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
