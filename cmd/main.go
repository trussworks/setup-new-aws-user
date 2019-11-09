package main

import (
	"bufio"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jessevdk/go-flags"
	qr "github.com/mdp/qrterminal"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
)

// TODO: How does it know my AWS username?
type cliOptions struct {
	AwsRegion      string `env:"AWS_REGION" long:"region" default:"us-west-2" description:"region"`
	AwsAccountID   int    `required:"true" env:"AWS_ACCOUNT_ID" long:"account_id" description:"account id"`
	AwsProfile     string `required:"true" env:"AWS_PROFILE" long:"profile" description:"profile name"`
	AwsRootProfile string `env:"AWS_ROOT_PROFILE" long:"root_profile" description:"root profile name"`
	AwsIDProfile   string `env:"AWS_ID_PROFILE" long:"id_profile" description:"id profile name"`
	Role           string `long:"role" choice:"admin-org-root" choice:"engineer" choice:"admin" description:"user role type"`
	Output         string `long:"output" default:"json" description:"aws-cli output format"`
}

var (
	options cliOptions
)

func text2qr(payload string) {
	// Generate a QRcode and print it to the terminal as text
	qrconfig := qr.Config{
		Level:     qr.M,      // redundancy level
		Writer:    os.Stdout, // where to print the result
		BlackChar: qr.BLACK,
		WhiteChar: qr.WHITE,
		QuietZone: 1, // size of the padding around it
	}
	// TODO: does this return err? if so, handle it
	qr.GenerateWithConfig(payload, qrconfig)
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

func setCfgKey(cfg *ini.File, section string, key string, value string) *ini.File {
	// Set a key value in an ini file
	_, err := cfg.Section(section).NewKey(key, value)
	if err != nil {
		log.Fatal(err)
	}

	return cfg
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

func createVirtualMfaDevice(iamSvc *iam.IAM) (string, string, error) {
	// Creates a virtual MFA device for the user specified in the AwsProfile
	// cli option. Returns mfaDeviceARN, mfaDeviceSerial, err

	// TODO: Finish dereferencing what we need from the new MFA device, and
	// return appropriate values

	// mfaDeviceInput := &iam.CreateVirtualMFADeviceInput{
	// 	VirtualMFADeviceName: aws.String(options.AwsProfile),
	// }
	// mfaDeviceOutput, err := iamSvc.CreateVirtualMFADevice(mfaDeviceInput)
	// if err != nil {
	// 	return "", "", err
	// }

	// https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#VirtualMFADevice
	// mfaDeviceSerial := *mfaDeviceOutput.VirtualMFADevice.SerialNumber

	// TODO: Enable the MFA device
	//       - Ask the user for MFA token(s) required by the EnableVirtualMFADevice call
	//       - Validate that the tokens are 6 character integers & store them so they
	//         can't be reused
	//       - Call EnableVirtualMFADevice
	//       - Check that the device is correct by polling ListVirtualMFADevices with
	//         assignment status "Assigned"
	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.EnableVirtualMFADevice
	//	https://docs.aws.amazon.com/sdk-for-go/api/service/iam/#IAM.ListVirtualMFADevices

	// TODO: return real mfaDeviceARN and mfaDeviceSerial
	return "arn:aws:iam::123456789012:mfa/foobar", "0123456789", nil
}

func configureAwsCliProfile(mfaArn string, profileArn string) error {
	// Sets up the configuration for the new profile in ~/.aws/config
	awsCfgPath := "my.ini.local" // TODO: Save to the real path

	cfgProfileName := fmt.Sprintf("profile %s", options.AwsProfile)

	// TODO: some of this logic is duplicated in checkAwsCfg
	awscfg := path.Join(os.Getenv("HOME"), ".aws", "config")
	iniFile, err := ini.Load(awscfg)
	if err != nil {
		return err
	}

	iniFile = setCfgKey(iniFile, cfgProfileName, "region", options.AwsRegion)
	iniFile = setCfgKey(
		iniFile, cfgProfileName, "mfa_serial", mfaArn,
	)
	iniFile = setCfgKey(
		iniFile, cfgProfileName, "role_arn", profileArn,
	)
	iniFile = setCfgKey(iniFile, cfgProfileName, "output", options.Output)

	// TODO: Back up the file before over writing it?
	err = iniFile.SaveTo(awsCfgPath)
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

	mfaArn, mfaSerial, err := createVirtualMfaDevice(iamSvc)
	if err != nil {
		log.Fatal(err)
	}

	// * Print the MFA serial as a QRcode
	text2qr(mfaSerial)

	// TODO: Activate the virtual MFA device

	// * Configure the AWS CLI profile
	log.Println("Configuring aws-cli...")

	getUserInput := &iam.GetUserInput{
		UserName: aws.String(options.AwsProfile),
	}
	getUserOutput, err := iamSvc.GetUser(getUserInput)
	if err != nil {
		log.Fatal(err)
	}

	profileArn := *getUserOutput.User.Arn

	err = configureAwsCliProfile(mfaArn, profileArn)
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
