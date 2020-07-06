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

// SetupUserInitFlags sets up the CLI flags for the 'setup' subcommand
func SetupUserInitFlags(flag *pflag.FlagSet) {

	flag.String(VaultAWSKeychainNameFlag, VaultAWSKeychainNameDefault, "The aws-vault keychain name")
	flag.StringSlice(AWSProfileAccountFlag, []string{}, "A comma separated list of AWS profiles and account IDs 'PROFILE1:ACCOUNTID1,PROFILE2:ACCOUNTID2,...'")
	flag.String(AWSBaseProfileFlag, "", fmt.Sprintf("The AWS base profile. If none provided will use first profile name from %q flag", AWSProfileAccountFlag))
	flag.String(AWSRegionFlag, endpoints.UsWest2RegionID, "The AWS region")
	flag.String(IAMUserFlag, "", "The IAM user name to setup")
	flag.String(IAMRoleFlag, "", "The IAM role name assigned to the user being setup")
	flag.String(OutputFlag, "json", "The AWS CLI output format")

	// No MFA Setup
	flag.Bool(NoMFAFlag, false, "When present do not provision an MFA device, assume one exists")

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level")

	flag.SortFlags = false
}

// SetupUserCheckConfig checks the CLI flag configuration for the 'setup' subcommand
func SetupUserCheckConfig(v *viper.Viper) error {

	if err := checkVault(v); err != nil {
		return fmt.Errorf("aws-vault check failed: %w", err)
	}

	if err := checkRegion(v); err != nil {
		return fmt.Errorf("Region check failed: %w", err)
	}

	if err := checkProfileAccount(v); err != nil {
		return fmt.Errorf("AWS Profile and Account ID check failed: %w", err)
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

// SetupConfig holds information for the AWS user being configured by this script
type SetupConfig struct {
	Logger     *log.Logger
	Config     *vault.ConfigFile
	QrTempFile *os.File
	Keyring    *keyring.Keyring
	NoMFA      bool

	IAMUser   string
	IAMRole   string
	Partition string
	Region    string
	Output    string

	BaseProfileName    string
	BaseProfile        *vault.ProfileSection
	AWSProfileAccounts []string
	AWSProfiles        []vault.ProfileSection
	MFASerial          string

	AccessKeyID     string
	SecretAccessKey string
}

// Setup orchestrates the tasks to create the user's MFA and rotate access
// keys.
func (sc *SetupConfig) Setup() {
	err := sc.PromptAccessCredentials()
	if err != nil {
		sc.Logger.Fatal(err)
	}

	err = sc.AddVaultProfile()
	if err != nil {
		sc.Logger.Fatal(err)
	}

	if sc.NoMFA {
		err = sc.GetMFADevice()
		if err != nil {
			sc.Logger.Fatal(err)
		}
	} else {
		err = sc.CreateVirtualMFADevice()
		if err != nil {
			sc.Logger.Fatal(err)
		}

		err = sc.EnableVirtualMFADevice()
		if err != nil {
			sc.Logger.Fatal(err)
		}
	}

	err = sc.UpdateAWSConfigFile()
	if err != nil {
		sc.Logger.Fatal(err)
	}

	err = sc.RemoveVaultSession()
	if err != nil {
		sc.Logger.Fatal(err)
	}

	err = sc.RotateAccessKeys()
	if err != nil {
		sc.Logger.Fatal(err)
	}

}

// PromptAccessCredentials prompts the user for their AWS access key ID and
// secret access key.
func (sc *SetupConfig) PromptAccessCredentials() error {
	accessKeyID, err := prompt.TerminalPrompt("Enter Access Key ID: ")
	if err != nil {
		return fmt.Errorf("error retrieving access key ID: %w", err)
	}

	secretKey, err := prompt.TerminalPrompt("Enter Secret Access Key: ")
	if err != nil {
		return fmt.Errorf("error retrieving secret access key: %w", err)
	}

	sc.AccessKeyID = accessKeyID
	sc.SecretAccessKey = secretKey

	return nil
}

func (sc *SetupConfig) newSession() (*session.Session, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: credentials.NewStaticCredentialsFromCreds(credentials.Value{
				AccessKeyID:     sc.AccessKeyID,
				SecretAccessKey: sc.SecretAccessKey,
			}),
			Region: aws.String(sc.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %w", err)
	}
	return sess, nil
}

func (sc *SetupConfig) newMFASession() (*session.Session, error) {
	mfaToken := promptMFAtoken("Third ", sc.Logger)
	basicSession, err := sc.newSession()
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %w", err)
	}
	stsClient := sts.New(basicSession)
	getSessionTokenOutput, err := stsClient.GetSessionToken(&sts.GetSessionTokenInput{
		SerialNumber: aws.String(sc.MFASerial),
		TokenCode:    aws.String(mfaToken),
	})
	if err != nil {
		sc.Logger.Fatalf("unable to get session token: %v", err)
	}
	mfaSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: credentials.NewStaticCredentialsFromCreds(credentials.Value{
				AccessKeyID:     *getSessionTokenOutput.Credentials.AccessKeyId,
				SecretAccessKey: *getSessionTokenOutput.Credentials.SecretAccessKey,
				SessionToken:    *getSessionTokenOutput.Credentials.SessionToken,
			}),
			Region: aws.String(sc.BaseProfile.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get MFA session: %w", err)
	}
	return mfaSession, nil
}

// GetMFADevice gets the user's existing virtual MFA device and updates the
// MFA serial in the profile field.
func (sc *SetupConfig) GetMFADevice() error {
	sc.Logger.Println("Getting the existing MFA device...")

	sess, err := sc.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

	mfaDeviceInput := &iam.ListMFADevicesInput{
		UserName: aws.String(sc.IAMUser),
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

	sc.MFASerial = *mfaDevice.SerialNumber

	return nil
}

// CreateVirtualMFADevice creates the user's virtual MFA device and updates the
// MFA serial in the profile field.
func (sc *SetupConfig) CreateVirtualMFADevice() error {
	sc.Logger.Println("Creating the virtual MFA device...")

	sess, err := sc.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

	mfaDeviceInput := &iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: aws.String(sc.IAMUser),
	}

	mfaDeviceOutput, err := svc.CreateVirtualMFADevice(mfaDeviceInput)
	if err != nil {
		return fmt.Errorf("unable to create virtual MFA: %w", err)
	}

	sc.MFASerial = *mfaDeviceOutput.VirtualMFADevice.SerialNumber

	// For the QR code, create a string that encodes:
	// otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String
	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
	content := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s",
		*mfaDeviceInput.VirtualMFADeviceName,
		sc.BaseProfile.Name,
		mfaDeviceOutput.VirtualMFADevice.Base32StringSeed,
	)

	err = generateQrCode(content, sc.QrTempFile)
	if err != nil {
		return fmt.Errorf("unable to generate qr code: %w", err)
	}
	err = openQrCode(sc.QrTempFile)
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
func (sc *SetupConfig) EnableVirtualMFADevice() error {
	sc.Logger.Println("Enabling the virtual MFA device")
	if sc.BaseProfile.MfaSerial == "" {
		return fmt.Errorf("profile MFA serial must be set")
	}

	mfaTokenPair := getMFATokenPair(sc.Logger)

	sess, err := sc.newSession()
	if err != nil {
		return fmt.Errorf("unable to get new session: %w", err)
	}
	svc := iam.New(sess)

	enableMFADeviceInput := &iam.EnableMFADeviceInput{
		AuthenticationCode1: aws.String(mfaTokenPair.Token1),
		AuthenticationCode2: aws.String(mfaTokenPair.Token2),
		SerialNumber:        aws.String(sc.BaseProfile.MfaSerial),
		UserName:            aws.String(sc.IAMUser),
	}

	_, err = svc.EnableMFADevice(enableMFADeviceInput)
	if err != nil {
		return fmt.Errorf("unable to enable MFA device: %w", err)
	}

	return nil
}

// RotateAccessKeys rotates the user's AWS access key.
func (sc *SetupConfig) RotateAccessKeys() error {
	sc.Logger.Println("Rotating AWS access keys")

	sc.Logger.Println("A new unique MFA token is needed to rotate the AWS access keys")
	sess, err := sc.newMFASession()
	if err != nil {
		return fmt.Errorf("unable to get mfa session: %w", err)
	}
	iamClient := iam.New(sess)
	listAccessKeysOutput, err := iamClient.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(sc.IAMUser),
	})
	if err != nil {
		return fmt.Errorf("unable to list access keys: %w", err)
	}

	if len(listAccessKeysOutput.AccessKeyMetadata) == maxNumAccessKeys {
		return fmt.Errorf("maximum of %v access keys have already been created for %s; delete your unused access key through the AWS console before trying again", maxNumAccessKeys, sc.IAMUser)
	}

	oldAccessKeyID := listAccessKeysOutput.AccessKeyMetadata[0].AccessKeyId

	sc.Logger.Println("Creating new access key")
	newAccessKey, err := iamClient.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: aws.String(sc.IAMUser),
	})
	if err != nil {
		return fmt.Errorf("unable to create new access key: %w", err)
	}

	sc.AccessKeyID = *newAccessKey.AccessKey.AccessKeyId
	sc.SecretAccessKey = *newAccessKey.AccessKey.SecretAccessKey

	err = sc.AddVaultProfile()
	if err != nil {
		return fmt.Errorf("unable to add new credentials to aws-vault profile: %w", err)
	}

	sc.Logger.Println("Deleting old access key")
	_, err = iamClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: oldAccessKeyID,
		UserName:    aws.String(sc.IAMUser),
	})

	if err != nil {
		return fmt.Errorf("unable to delete old access key: %w", err)
	}

	return nil
}

// AddVaultProfile uses aws-vault to store AWS credentials for the user's
// profile.
func (sc *SetupConfig) AddVaultProfile() error {
	creds := credentials.Value{AccessKeyID: sc.AccessKeyID, SecretAccessKey: sc.SecretAccessKey}

	ckr := &vault.CredentialKeyring{Keyring: *sc.Keyring}
	errSet := ckr.Set(sc.BaseProfileName, creds)
	if errSet != nil {
		return fmt.Errorf("unable to set base profile credentials: %w", errSet)
	}

	sc.Logger.Printf("Added credentials to profile %q in vault", sc.BaseProfileName)

	err := deleteSession(sc.BaseProfileName, sc.Keyring, sc.Logger)
	if err != nil {
		return fmt.Errorf("unable to delete session: %w", err)
	}

	return nil
}

// UpdateAWSProfile updates or creates a single AWS profile to the AWS config file
func (sc *SetupConfig) UpdateAWSProfile(iniFile *ini.File, profile *vault.ProfileSection, sourceProfile *string) error {
	sc.Logger.Printf("Adding the profile %q to the AWS config file", profile.Name)
	sectionName := fmt.Sprintf("profile %s", profile.Name)

	// Get or create section before updating
	var err error
	var section *ini.Section
	section = iniFile.Section(sectionName)
	if section == nil {
		section, err = iniFile.NewSection(sectionName)
		if err != nil {
			return fmt.Errorf("error creating section %q: %w", profile.Name, err)
		}
	}

	// Add the source profile when provided
	if sourceProfile != nil {
		_, err = section.NewKey("source_profile", *sourceProfile)
		if err != nil {
			return fmt.Errorf("unable to add source profile: %w", err)
		}
	}

	if err = section.ReflectFrom(&profile); err != nil {
		return fmt.Errorf("error mapping profile to ini file: %w", err)
	}
	_, err = section.NewKey("output", sc.Output)
	if err != nil {
		return fmt.Errorf("unable to add output key: %w", err)
	}
	return nil
}

// UpdateAWSConfigFile adds the user's AWS profile to the AWS config file
func (sc *SetupConfig) UpdateAWSConfigFile() error {
	sc.Logger.Printf("Updating the AWS config file: %s", sc.Config.Path)

	// load the ini file
	iniFile, err := ini.Load(sc.Config.Path)
	if err != nil {
		return fmt.Errorf("unable to load aws config file: %w", err)
	}

	sc.BaseProfile = &vault.ProfileSection{
		Name:   sc.BaseProfileName,
		Region: sc.Region,
	}

	// Add the base profile
	if err := sc.UpdateAWSProfile(iniFile, sc.BaseProfile, nil); err != nil {
		return fmt.Errorf("could not add base profile: %w", err)
	}

	// Add each of the remaining profiles
	for _, profileAccount := range sc.AWSProfileAccounts {
		profileAccountParts := strings.Split(profileAccount, ":")
		profileName := profileAccountParts[0]
		accountID := profileAccountParts[1]

		roleProfile := vault.ProfileSection{
			Name:      profileName,
			Region:    sc.Region,
			MfaSerial: sc.MFASerial,

			// Each account assumes a role that is added to the config profile
			RoleARN: fmt.Sprintf("arn:%s:iam::%s:role/%s",
				sc.Partition,
				accountID,
				sc.IAMRole),
		}
		sc.AWSProfiles = append(sc.AWSProfiles, roleProfile)

		// Add the role profile with base as the source profile
		if err := sc.UpdateAWSProfile(iniFile, &roleProfile, &sc.BaseProfile.Name); err != nil {
			return fmt.Errorf("could not add role profile: %w", err)
		}
	}

	// save it back to the aws config path
	return iniFile.SaveTo(sc.Config.Path)
}

// RemoveVaultSession removes the aws-vault session for the profile.
func (sc *SetupConfig) RemoveVaultSession() error {
	sc.Logger.Printf("Removing aws-vault session")
	err := deleteSession(sc.BaseProfile.Name, sc.Keyring, sc.Logger)
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

func deleteSession(profile string, keyring *keyring.Keyring, logger *log.Logger) error {
	credsKeyring := vault.CredentialKeyring{Keyring: *keyring}
	sessions := credsKeyring.Sessions()

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
	checkConfigErr := SetupUserCheckConfig(v)
	if checkConfigErr != nil {
		return checkConfigErr
	}

	// Get command line flag values
	awsRegion := v.GetString(AWSRegionFlag)
	awsVaultKeychainName := v.GetString(VaultAWSKeychainNameFlag)
	awsProfileAccount := v.GetStringSlice(AWSProfileAccountFlag)
	awsBaseProfile := v.GetString(AWSBaseProfileFlag)
	iamUser := v.GetString(IAMUserFlag)
	iamRole := v.GetString(IAMRoleFlag)
	output := v.GetString(OutputFlag)
	noMFA := v.GetBool(NoMFAFlag)

	// Get base profile
	if len(awsBaseProfile) == 0 {
		awsBaseProfile = strings.Split(awsProfileAccount[0], ":")[0]
	}

	// Validator used to validate input options for MFA
	validate = validator.New()

	// initialize things
	partition, err := getPartition(awsRegion)
	if err != nil {
		logger.Fatal(err)
	}

	baseProfileName := fmt.Sprintf("%s-base", awsBaseProfile)

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

	setupConfig := SetupConfig{
		// Config
		Logger:     logger,
		Config:     config,
		QrTempFile: tempfile,
		Keyring:    keyring,
		NoMFA:      noMFA,

		// Profile Inputs
		IAMUser:   iamUser,
		IAMRole:   iamRole,
		Region:    awsRegion,
		Partition: partition,
		Output:    output,

		// Profiles
		BaseProfileName:    baseProfileName,
		AWSProfileAccounts: awsProfileAccount,
	}

	setupConfig.Setup()

	// If we got this far, we win
	logger.Println("Victory!")

	return nil
}
