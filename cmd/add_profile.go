package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/99designs/aws-vault/vault"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/ini.v1"
)

// AddProfileInitFlags sets up the CLI flags for the 'add-profile' subcommand
func AddProfileInitFlags(flag *pflag.FlagSet) {

	flag.String(VaultAWSKeychainNameFlag, VaultAWSKeychainNameDefault, "The aws-vault keychain name")
	flag.StringSlice(AWSProfileAccountFlag, []string{}, "A comma separated list of AWS profiles and account IDs 'PROFILE1:ACCOUNTID1,PROFILE2:ACCOUNTID2,...'")
	flag.String(AWSBaseProfileFlag, "", fmt.Sprintf("The AWS base profile. If none provided will use first profile name from %q flag", AWSProfileAccountFlag))
	flag.String(AWSRegionFlag, endpoints.UsWest2RegionID, "The AWS region")
	flag.String(IAMUserFlag, "", "The IAM user name to setup")
	flag.String(IAMRoleFlag, "", "The IAM role name assigned to the user being setup")
	flag.String(OutputFlag, "json", "The AWS CLI output format")

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level")

	flag.SortFlags = false
}

// AddProfileCheckConfig checks the CLI flag configuration for the 'add-profile' subcommand
func AddProfileCheckConfig(v *viper.Viper) error {

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

// AddProfile adds a new profile to the AWS config file
func (sc *SetupConfig) AddProfile() error {

	sc.Logger.Printf("Adding new profiles to the AWS config file: %s", sc.Config.Path)

	// load the ini file
	iniFile, err := ini.Load(sc.Config.Path)
	if err != nil {
		return fmt.Errorf("unable to load aws config file: %w", err)
	}

	// save it back to the aws config path
	return iniFile.SaveTo(sc.Config.Path)
}

func addProfileFunction(cmd *cobra.Command, args []string) error {
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
	checkConfigErr := AddProfileCheckConfig(v)
	if checkConfigErr != nil {
		return checkConfigErr
	}

	// Get command line flag values
	awsRegion := v.GetString(AWSRegionFlag)
	awsVaultKeychainName := v.GetString(VaultAWSKeychainNameFlag)
	// awsProfileAccount := v.GetStringSlice(AWSProfileAccountFlag)
	iamUser := v.GetString(IAMUserFlag)
	iamRole := v.GetString(IAMRoleFlag)
	output := v.GetString(OutputFlag)

	// Validator used to validate input options for MFA
	validate = validator.New()

	// initialize things
	partition, err := getPartition(awsRegion)
	if err != nil {
		logger.Fatal(err)
	}

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
		Logger:  logger,
		Config:  config,
		Keyring: keyring,

		// Profile Inputs
		IAMUser:   iamUser,
		IAMRole:   iamRole,
		Region:    awsRegion,
		Partition: partition,
		Output:    output,

		// RoleProfileName: &awsVaultProfileAccount[0],
		// NewProfiles:     awsVaultProfileAccount[1:],
	}

	if err := setupConfig.AddProfile(); err != nil {
		logger.Fatal(err)
	}

	// If we got this far, we win
	logger.Println("Victory!")

	return nil
}
