package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/browser"
	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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

func setupUserInitFlags(flag *pflag.FlagSet) {

	flag.String(VaultAWSKeychainNameFlag, VaultAWSKeychainNameDefault, "The aws-vault keychain name")
	flag.String(VaultAWSProfileFlag, "", "The aws-vault profile name")
	flag.String(AWSRegionFlag, endpoints.UsWest2RegionID, "The AWS region")
	flag.String(AWSAccountIDFlag, "", "The AWS account ID")
	flag.String(IAMUserFlag, "", "The IAM user name to setup")
	flag.String(IAMRoleFlag, "", "The IAM role name assigned to the user being setup")
	flag.String(OutputFlag, "json", "The AWS CLI output format")

	// No MFA Setup
	flag.Bool(NoMFAFlag, false, "When present do not provision an MFA device, assume one exists")

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level")

	flag.SortFlags = false
}

func setupUserCheckConfig(v *viper.Viper) error {

	if err := checkVault(v); err != nil {
		return fmt.Errorf("aws-vault check failed: %w", err)
	}

	if err := checkRegion(v); err != nil {
		return fmt.Errorf("Region check failed: %w", err)
	}

	if err := checkAccountID(v); err != nil {
		return fmt.Errorf("Account ID check failed: %w", err)
	}

	if err := checkIAMUser(v); err != nil {
		return fmt.Errorf("IAM User check failed: %w", err)
	}

	if err := checkIAMRole(v); err != nil {
		return fmt.Errorf("IAM Role check failed: %w", err)
	}

	if err := checkOutput(v); err != nil {
		return fmt.Errorf("Output check failed: %w", err)
	}

	return nil
}

// User holds information for the AWS user being configured by this script
type User struct {
	Logger          *log.Logger
	Name            string
	BaseProfile     *vault.Profile
	RoleProfile     *vault.Profile
	Output          string
	Config          *vault.Config
	AccessKeyID     string
	SecretAccessKey string
	QrTempFile      *os.File
	Keyring         *keyring.Keyring
	NoMFA           bool
}

// Setup orchestrates the tasks to create the user's MFA and rotate access
// keys.
func (u *User) Setup() {
	err := u.PromptAccessCredentials()
	if err != nil {
		u.Logger.Fatal(err)
	}

	err = u.AddVaultProfile()
	if err != nil {
		u.Logger.Fatal(err)
	}

	if u.NoMFA {
		err = u.GetMFADevice()
		if err != nil {
			u.Logger.Fatal(err)
		}
	} else {
		err = u.CreateVirtualMFADevice()
		if err != nil {
			u.Logger.Fatal(err)
		}

		err = u.EnableVirtualMFADevice()
		if err != nil {
			u.Logger.Fatal(err)
		}
	}

	err = u.UpdateAWSConfigFile()
	if err != nil {
		u.Logger.Fatal(err)
	}

	err = u.RemoveVaultSession()
	if err != nil {
		u.Logger.Fatal(err)
	}

	err = u.RotateAccessKeys()
	if err != nil {
		u.Logger.Fatal(err)
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
			Region: aws.String(u.BaseProfile.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %w", err)
	}
	return sess, nil
}

func (u *User) newMFASession() (*session.Session, error) {
	mfaToken := promptMFAtoken("Third ", u.Logger)
	basicSession, err := u.newSession()
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %w", err)
	}
	stsClient := sts.New(basicSession)
	getSessionTokenOutput, err := stsClient.GetSessionToken(&sts.GetSessionTokenInput{
		SerialNumber: aws.String(u.BaseProfile.MFASerial),
		TokenCode:    aws.String(mfaToken),
	})
	if err != nil {
		u.Logger.Fatalf("unable to get session token: %v", err)
	}
	mfaSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: credentials.NewStaticCredentialsFromCreds(credentials.Value{
				AccessKeyID:     *getSessionTokenOutput.Credentials.AccessKeyId,
				SecretAccessKey: *getSessionTokenOutput.Credentials.SecretAccessKey,
				SessionToken:    *getSessionTokenOutput.Credentials.SessionToken,
			}),
			Region: aws.String(u.BaseProfile.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get MFA session: %w", err)
	}
	return mfaSession, nil
}

// GetMFADevice gets the user's existing virtual MFA device and updates the
// MFA serial in the profile field.
func (u *User) GetMFADevice() error {
	u.Logger.Println("Getting the existing MFA device...")

	sess, err := u.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

	mfaDeviceInput := &iam.ListMFADevicesInput{
		UserName: aws.String(u.Name),
	}

	mfaDeviceOutput, err := svc.ListMFADevices(mfaDeviceInput)
	if err != nil {
		return fmt.Errorf("unable to get MFA: %w", err)
	}

	if len(mfaDeviceOutput.MFADevices) == 0 {
		return errors.New("no MFA devices registered")
	}
	if len(mfaDeviceOutput.MFADevices) > 1 {
		return errors.New("more than one MFA device registered, no way to choose")
	}
	mfaDevice := mfaDeviceOutput.MFADevices[0]

	u.BaseProfile.MFASerial = *mfaDevice.SerialNumber
	u.RoleProfile.MFASerial = *mfaDevice.SerialNumber

	return nil
}

// CreateVirtualMFADevice creates the user's virtual MFA device and updates the
// MFA serial in the profile field.
func (u *User) CreateVirtualMFADevice() error {
	u.Logger.Println("Creating the virtual MFA device...")

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
		return fmt.Errorf("unable to create virtual MFA: %w", err)
	}

	u.BaseProfile.MFASerial = *mfaDeviceOutput.VirtualMFADevice.SerialNumber
	u.RoleProfile.MFASerial = *mfaDeviceOutput.VirtualMFADevice.SerialNumber

	// For the QR code, create a string that encodes:
	// otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String
	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
	content := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s",
		*mfaDeviceInput.VirtualMFADeviceName,
		u.BaseProfile.Name,
		mfaDeviceOutput.VirtualMFADevice.Base32StringSeed,
	)

	err = generateQrCode(content, u.QrTempFile)
	if err != nil {
		return fmt.Errorf("unable to generate qr code: %w", err)
	}
	err = openQrCode(u.QrTempFile)
	if err != nil {
		return fmt.Errorf("unable to open qr code png: %w", err)
	}

	return nil
}

func promptMFAtoken(messagePrefix string, logger *log.Logger) string {
	var token string
	for attempts := maxMFATokenPromptAttempts; token == "" && attempts > 0; attempts-- {
		t, err := prompt.TerminalPrompt(fmt.Sprintf("%sMFA token (%d attempts remaining): ", messagePrefix, attempts))
		if err != nil {
			logger.Println(err)
			continue
		}
		err = validate.Var(t, "numeric,len=6")
		if err != nil {
			logger.Println("MFA token must be 6 digits. Please try again.")
			continue
		}
		token = t
	}
	return token
}

func getMFATokenPair(logger *log.Logger) MFATokenPair {
	var mfaTokenPair MFATokenPair
	for attempts := maxMFATokenPromptAttempts; attempts > 0; attempts-- {
		logger.Printf("Two unique MFA tokens needed to activate MFA device (%d attempts remaining)\n", attempts)
		authToken1 := promptMFAtoken("First ", logger)
		authToken2 := promptMFAtoken("Second ", logger)

		mfaTokenPair = MFATokenPair{
			Token1: authToken1,
			Token2: authToken2,
		}
		err := validate.Struct(mfaTokenPair)
		if err != nil {
			logger.Println(err)
		} else {
			break
		}
	}
	return mfaTokenPair
}

// EnableVirtualMFADevice enables the user's MFA device
func (u *User) EnableVirtualMFADevice() error {
	u.Logger.Println("Enabling the virtual MFA device")
	if u.BaseProfile.MFASerial == "" {
		return fmt.Errorf("profile MFA serial must be set")
	}

	mfaTokenPair := getMFATokenPair(u.Logger)

	sess, err := u.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

	enableMFADeviceInput := &iam.EnableMFADeviceInput{
		AuthenticationCode1: aws.String(mfaTokenPair.Token1),
		AuthenticationCode2: aws.String(mfaTokenPair.Token2),
		SerialNumber:        aws.String(u.BaseProfile.MFASerial),
		UserName:            aws.String(u.Name),
	}

	_, err = svc.EnableMFADevice(enableMFADeviceInput)
	if err != nil {
		return fmt.Errorf("unable to enable MFA device: %w", err)
	}

	return nil
}

// RotateAccessKeys rotates the user's AWS access key.
func (u *User) RotateAccessKeys() error {
	u.Logger.Println("Rotating AWS access keys")

	u.Logger.Println("A new unique MFA token is needed to rotate the AWS access keys")
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

	u.Logger.Println("Creating new access key")
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

	u.Logger.Println("Deleting old access key")
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
	creds := credentials.Value{AccessKeyID: u.AccessKeyID, SecretAccessKey: u.SecretAccessKey}
	provider := &vault.KeyringProvider{Keyring: *u.Keyring, Profile: u.BaseProfile.Name}

	err := provider.Store(creds)
	if err != nil {
		return fmt.Errorf("unable to store credentials: %w", err)
	}

	u.Logger.Printf("Added credentials to profile %q in vault", u.BaseProfile.Name)

	err = deleteSession(u.BaseProfile.Name, u.Config, u.Keyring, u.Logger)
	if err != nil {
		return fmt.Errorf("unable to delete session: %w", err)
	}

	return nil
}

// UpdateAWSConfigFile adds the user's AWS profile to the AWS config file
func (u *User) UpdateAWSConfigFile() error {
	u.Logger.Printf("Updating the AWS config file: %s", u.Config.Path)
	// load the ini file
	iniFile, err := ini.Load(u.Config.Path)
	if err != nil {
		return fmt.Errorf("unable to load aws config file: %w", err)
	}
	// add the base profile
	baseSectionName := fmt.Sprintf("profile %s", u.BaseProfile.Name)
	baseSection, err := iniFile.NewSection(baseSectionName)
	if err != nil {
		return fmt.Errorf("error creating section %q: %w", u.BaseProfile.Name, err)
	}
	if err = baseSection.ReflectFrom(&u.BaseProfile); err != nil {
		return fmt.Errorf("error mapping profile to ini file: %w", err)
	}
	_, err = baseSection.NewKey("output", u.Output)
	if err != nil {
		return fmt.Errorf("unable to add output key: %w", err)
	}

	// add the role profile
	roleSectionName := fmt.Sprintf("profile %s", u.RoleProfile.Name)
	roleSection, err := iniFile.NewSection(roleSectionName)
	if err != nil {
		return fmt.Errorf("error creating section %q: %w", u.RoleProfile.Name, err)
	}
	_, err = roleSection.NewKey("source_profile", u.BaseProfile.Name)
	if err != nil {
		return fmt.Errorf("unable to add source profile: %w", err)
	}
	if err = roleSection.ReflectFrom(&u.RoleProfile); err != nil {
		return fmt.Errorf("error mapping profile to ini file: %w", err)
	}
	_, err = roleSection.NewKey("output", u.Output)
	if err != nil {
		return fmt.Errorf("unable to add output key: %w", err)
	}

	// save it back to the aws config path
	return iniFile.SaveTo(u.Config.Path)
}

// RemoveVaultSession removes the aws-vault session for the profile.
func (u *User) RemoveVaultSession() error {
	u.Logger.Printf("Removing aws-vault session")
	err := deleteSession(u.BaseProfile.Name, u.Config, u.Keyring, u.Logger)
	if err != nil {
		return fmt.Errorf("unable to delete session: %w", err)
	}

	return nil
}

func getKeyring(keychainName string) (*keyring.Keyring, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "aws-vault",
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.FileBackend,
		},
		KeychainName:             keychainName,
		KeychainTrustApplication: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error opening keyring: %w", err)
	}

	return &ring, nil
}

func deleteSession(profile string, awsConfig *vault.Config, keyring *keyring.Keyring, logger *log.Logger) error {
	sessions, err := vault.NewKeyringSessions(*keyring, awsConfig)
	if err != nil {
		return fmt.Errorf("unable to create new keyring session: %w", err)
	}

	if n, _ := sessions.Delete(profile); n > 0 {
		logger.Printf("Deleted %d existing sessions.\n", n)
	}

	return nil
}

func generateQrCode(payload string, tempFile *os.File) error {
	// Creates QR Code
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("unable to create qr code: %w", err)
	}

	// Generates a QR PNG 256 x 256, returns []byte
	qr, err := q.PNG(256)
	if err != nil {
		return fmt.Errorf("unable to generate PNG: %w", err)
	}

	// Write the QR PNG to the Temp File
	if _, err := tempFile.Write(qr); err != nil {
		_ = tempFile.Close()
		return err
	}
	return nil
}

func openQrCode(tempFile *os.File) error {
	err := browser.OpenFile(tempFile.Name())
	if err != nil {
		return fmt.Errorf("unable to open QR Code PNG: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("unable to close QR Code: %w", err)
	}
	return nil
}

func getPartition(region string) (string, error) {
	partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !ok {
		return "", fmt.Errorf("Error finding partition for region: %s", region)
	}
	return partition.ID(), nil
}

func setupUserFunction(cmd *cobra.Command, args []string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()

	err := cmd.ParseFlags(args)
	if err != nil {
		return err
	}

	flag := cmd.Flags()

	v := viper.New()
	bindErr := v.BindPFlags(flag)
	if bindErr != nil {
		return bindErr
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	// Create the logger
	// Remove the prefix and any datetime data
	logger := log.New(os.Stdout, "", log.LstdFlags)

	verbose := v.GetBool(VerboseFlag)
	if !verbose {
		// Disable any logging that isn't attached to the logger unless using the verbose flag
		log.SetOutput(ioutil.Discard)
		log.SetFlags(0)

		// Remove the flags for the logger
		logger.SetFlags(0)
	}

	// Check the config and exit with usage details if there is a problem
	checkConfigErr := setupUserCheckConfig(v)
	if checkConfigErr != nil {
		return checkConfigErr
	}

	// Get command line flag values
	awsRegion := v.GetString(AWSRegionFlag)
	awsAccountID := v.GetString(AWSAccountIDFlag)
	awsVaultKeychainName := v.GetString(VaultAWSKeychainNameFlag)
	awsVaultProfile := v.GetString(VaultAWSProfileFlag)
	iamUser := v.GetString(IAMUserFlag)
	iamRole := v.GetString(IAMRoleFlag)
	output := v.GetString(OutputFlag)
	noMFA := v.GetBool(NoMFAFlag)

	// Validator used to validate input options for MFA
	validate = validator.New()

	// initialize things
	partition, err := getPartition(awsRegion)
	if err != nil {
		logger.Fatal(err)
	}

	baseProfile := vault.Profile{
		Name: fmt.Sprintf("%s-base",
			awsVaultProfile,
		),
		Region: awsRegion,
	}

	roleProfile := vault.Profile{
		Name: awsVaultProfile,
		RoleARN: fmt.Sprintf("arn:%s:iam::%s:role/%s",
			partition,
			awsAccountID,
			iamRole),
		Region: awsRegion,
	}

	// Create a Temp File
	tempfile, err := ioutil.TempFile("", "temp-qr.*.png")
	if err != nil {
		logger.Fatal(err)
	}
	// Cleanup after ourselves
	defer func() {
		errRemove := os.Remove(tempfile.Name())
		if errRemove != nil {
			logger.Fatal(errRemove)
		}
	}()

	config, err := vault.LoadConfigFromEnv()
	if err != nil {
		logger.Fatal(err)
	}

	keyring, err := getKeyring(awsVaultKeychainName)
	if err != nil {
		logger.Fatal(err)
	}
	user := User{
		Logger:      logger,
		Name:        iamUser,
		BaseProfile: &baseProfile,
		RoleProfile: &roleProfile,
		Output:      output,
		Config:      config,
		QrTempFile:  tempfile,
		Keyring:     keyring,
		NoMFA:       noMFA,
	}
	user.Setup()

	// If we got this far, we win
	logger.Println("Victory!")

	return nil
}
