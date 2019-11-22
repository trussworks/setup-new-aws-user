package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/99designs/aws-vault/vault"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jessevdk/go-flags"
	"github.com/skip2/go-qrcode"
	"gopkg.in/ini.v1"
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

func (c *cliOptions) checkProfileVars() error {
	if c.AwsProfile != c.AwsRootProfile && c.AwsProfile != c.AwsIDProfile {
		return fmt.Errorf("found AWS_PROFILE=%q, expecting AWS_PROFILE to match AWS_ROOT_PROFILE (%q) or AWS_ID_PROFILE (%q); there are no users in other accounts, just roles",
			c.AwsProfile,
			c.AwsRootProfile,
			c.AwsIDProfile,
		)
	}
	return nil
}

var (
	options cliOptions
)

func text2qr(payload string) {
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(q.ToSmallString(false))
}

func checkAwsCfg() {
	log.Printf("Checking that the profile %q does not already exist in the aws-cli config", options.AwsProfile)

	awscfg := path.Join(os.Getenv("HOME"), ".aws", "config")
	cfg, err := ini.Load(awscfg)
	if err != nil {
		log.Fatal(err)
	}

	secs := cfg.Sections()

	for _, section := range secs {
		if section.Name() == fmt.Sprintf("profile %s", options.AwsProfile) {
			log.Fatalf("Profile %q already exists! If you want to replace it, delete the existing profile in your ~/.aws/config file.", options.AwsProfile)
		}
	}
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

func readLine(prompt string) (string, error) {
	// Prompt the user for input, and return the input
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(prompt)

	input, err := reader.ReadString('\n')
	if err != nil {
		return input, err
	}

	input = strings.TrimSuffix(input, "\n")

	return input, nil
}

func getAccessKey() (string, string, error) {
	// Get temporary access keys from the user
	accessKeyID, err := readLine("Enter temporary AWS Access Key ID: ")
	if err != nil {
		return accessKeyID, "", err
	}

	accessKeySecret, err := readLine("Enter temporary AWS Secret Access Key: ")
	if err != nil {
		return accessKeyID, "", err
	}

	return accessKeyID, accessKeySecret, nil
}

func checkStsAccess(stsSvc *sts.STS) error {
	log.Println("Testing access to AWS...")

	input := &sts.GetCallerIdentityInput{}
	_, err := stsSvc.GetCallerIdentity(input)
	if err != nil {
		return err
	}

	return nil
}

// Creates a virtual MFA device for the user specified in the AwsProfile
// cli option. Returns mfaDeviceSerial, err
func createVirtualMfaDevice(iamSvc *iam.IAM) (string, error) {
	mfaDeviceInput := &iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: aws.String(options.IAMUser),
	}

	mfaDeviceOutput, err := iamSvc.CreateVirtualMFADevice(mfaDeviceInput)
	if err != nil {
		return "", err
	}

	// For the QR code, create a string that encodes:
	// otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String
	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
	content := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s",
		*mfaDeviceInput.VirtualMFADeviceName,
		options.AwsProfile,
		mfaDeviceOutput.VirtualMFADevice.Base32StringSeed,
	)

	text2qr(content)

	return *mfaDeviceOutput.VirtualMFADevice.SerialNumber, nil
}

func enableVirtualMFADevice(iamSvc *iam.IAM, mfaSerial string) {
	// TODO:
	// - Validate that the tokens are 6 character integers & store them so they
	//   can't be reused
	// - Check that the device is correct by polling ListVirtualMFADevices with
	//   assignment status "Assigned"
	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.EnableVirtualMFADevice
	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.ListVirtualMFADevices

	// get two auth codes from user
	authToken1, err := readLine("First MFA token: ")
	if err != nil {
		log.Fatal(err)
	}
	authToken2, err := readLine("Second MFA token: ")
	if err != nil {
		log.Fatal(err)
	}
	enableMFADeviceInput := &iam.EnableMFADeviceInput{
		AuthenticationCode1: aws.String(authToken1),
		AuthenticationCode2: aws.String(authToken2),
		SerialNumber:        aws.String(mfaSerial),
		UserName:            aws.String(options.IAMUser),
	}

	_, err = iamSvc.EnableMFADevice(enableMFADeviceInput)
	if err != nil {
		log.Fatal(err)
	}
}

func configureAwsCliProfile(mfaArn string, profileArn string) error {
	configFile, err := vault.LoadConfigFromEnv()
	if err != nil {
		return err
	}

	profileSection := vault.Profile{
		Name:      options.AwsProfile,
		MFASerial: mfaArn,
		RoleARN:   profileArn,
		Region:    options.AwsRegion,
	}

	err = configFile.Add(profileSection)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	parser := flags.NewParser(&options, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatal(err)
	}

	// check aws profile environment variables
	err = options.checkProfileVars()
	if err != nil {
		log.Fatal(err)
	}

	// * Verify that the profile does not exist in the AWS cli config
	checkAwsCfg()

	// * Get the user's temporary access credentials
	accessKeyID, accessKeySecret, err := getAccessKey()
	if err != nil {
		log.Fatal(err)
	}

	// AWS sdk will not read authentication crendentials as arguments to a
	// function call. Since we don't want to use the aws-cli config at this
	// point, we verify that the env vars are set
	os.Setenv("AWS_PROFILE", options.AwsProfile)
	os.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", accessKeySecret)

	// Create STS and IAM sessions
	sessionOpts := session.Options{
		Config: aws.Config{
			// Why aws.String(): https://github.com/aws/aws-sdk-go/issues/363
			Region:                        aws.String(options.AwsRegion),
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
	}
	sess, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		log.Fatal(err)
	}

	stsSvc := sts.New(sess)
	iamSvc := iam.New(sess)

	// * Verify access to AWS using the temporary credentials we have
	log.Println("Checking STS access...")

	err = checkStsAccess(stsSvc)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Success!")
	}

	// * Create the virtual MFA device
	log.Println("Creating the virtual MFA device...")

	mfaSerial, err := createVirtualMfaDevice(iamSvc)
	if err != nil {
		log.Fatal(err)
	}

	enableVirtualMFADevice(iamSvc, mfaSerial)

	// * Configure the AWS CLI profile
	log.Println("Configuring aws-cli...")

	getUserInput := &iam.GetUserInput{
		UserName: aws.String(options.IAMUser),
	}
	_, err = iamSvc.GetUser(getUserInput)
	if err != nil {
		log.Fatal(err)
	}

	profileArn := fmt.Sprintf("arn:aws:iam::%v:role/%v",
		options.AwsAccountID, options.Role)

	err = configureAwsCliProfile(mfaSerial, profileArn)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Success!")
	}

	// * Verify access to AWS using the newly created MFA device & config file
	//   We unset the environment variables to ensure the access keys are read
	//   from the keyring
	log.Println("Checking STS access...")
	os.Unsetenv("AWS_ACCESS_KEY_ID")
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")

	err = checkStsAccess(stsSvc)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Success!")
	}

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
