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

	flag.StringSlice(AWSProfileAccountFlag, []string{}, "A comma separated list of AWS profiles and account IDs 'PROFILE1:ACCOUNTID1,PROFILE2:ACCOUNTID2,...'")
	flag.String(AWSProfileFlag, "", "The AWS profile used to get the source_profile and mfa_serial attributes")
	flag.String(AWSRegionFlag, endpoints.UsWest2RegionID, "The AWS region")
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

	if err := checkIAMRole(v); err != nil {
		return fmt.Errorf("IAM Role check failed: %w", err)
	}

	if err := checkOutput(v); err != nil {
		return fmt.Errorf("Output check failed: %w", err)
	}

	return nil
}

// AddProfileConfig holds information for the AWS user being configured by this script
type AddProfileConfig struct {
	Logger *log.Logger
	Config *vault.ConfigFile

	IAMRole   string
	Partition string
	Region    string
	Output    string

	BaseProfileName    string
	AWSProfileName     string
	AWSProfileAccounts []string
	AWSProfiles        []vault.ProfileSection
	MFASerial          string
}

// UpdateAWSProfile updates or creates a single AWS profile to the AWS config file
func (apc *AddProfileConfig) UpdateAWSProfile(iniFile *ini.File, profile *vault.ProfileSection, sourceProfile *string) error {
	apc.Logger.Printf("Adding the profile %q to the AWS config file", profile.Name)
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
	_, err = section.NewKey("output", apc.Output)
	if err != nil {
		return fmt.Errorf("unable to add output key: %w", err)
	}
	return nil
}

// AddProfile adds a new profile to the AWS config file
func (apc *AddProfileConfig) AddProfile() error {

	apc.Logger.Printf("Adding new profiles to the AWS config file: %s", apc.Config.Path)

	// load the ini file
	iniFile, err := ini.Load(apc.Config.Path)
	if err != nil {
		return fmt.Errorf("unable to load aws config file: %w", err)
	}

	roleProfileSection := iniFile.Section(fmt.Sprintf("profile %s", apc.AWSProfileName))
	// Get the source profile
	sourceProfileKey, err := roleProfileSection.GetKey("source_profile")
	if err != nil {
		return fmt.Errorf("Unable to get source profile from %q: %w", apc.AWSProfileName, err)
	}
	apc.BaseProfileName = sourceProfileKey.String()

	// Get the MFA Serial
	mfaSerialKey, err := roleProfileSection.GetKey("mfa_serial")
	if err != nil {
		return err
	}
	apc.MFASerial = mfaSerialKey.String()

	// Add each of the remaining profiles
	for _, profileAccount := range apc.AWSProfileAccounts {
		profileAccountParts := strings.Split(profileAccount, ":")
		profileName := profileAccountParts[0]
		accountID := profileAccountParts[1]

		roleProfile := vault.ProfileSection{
			Name:      profileName,
			Region:    apc.Region,
			MfaSerial: apc.MFASerial,

			// Each account assumes a role that is added to the config profile
			RoleARN: fmt.Sprintf("arn:%s:iam::%s:role/%s",
				apc.Partition,
				accountID,
				apc.IAMRole),
		}
		apc.AWSProfiles = append(apc.AWSProfiles, roleProfile)

		// Add the role profile with base as the source profile
		if err := apc.UpdateAWSProfile(iniFile, &roleProfile, &apc.BaseProfileName); err != nil {
			return err
		}
	}

	// save it back to the aws config path
	return iniFile.SaveTo(apc.Config.Path)
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
	awsProfileAccount := v.GetStringSlice(AWSProfileAccountFlag)
	awsProfile := v.GetString(AWSProfileFlag)
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

	addProfileConfig := AddProfileConfig{
		// Config
		Logger: logger,
		Config: config,

		// Profile Inputs
		IAMRole:   iamRole,
		Region:    awsRegion,
		Partition: partition,
		Output:    output,

		// Profiles
		AWSProfileAccounts: awsProfileAccount,
		AWSProfileName:     awsProfile,
	}

	if err := addProfileConfig.AddProfile(); err != nil {
		logger.Fatal(err)
	}

	// If we got this far, we win
	logger.Println("Victory!")

	return nil
}
