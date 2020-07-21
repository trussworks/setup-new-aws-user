package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/spf13/viper"
)

const (
	// AWSRegionFlag is the generic AWS Region Flag
	AWSRegionFlag string = "aws-region"

	// VaultAWSKeychainNameFlag is the aws-vault keychain name Flag
	VaultAWSKeychainNameFlag string = "aws-vault-keychain-name"
	// VaultAWSKeychainNameDefault is the aws-vault default keychain name
	VaultAWSKeychainNameDefault string = "login"

	// AWSProfileAccountFlag is the combined AWS profile name and account ID Flag
	AWSProfileAccountFlag string = "aws-profile-account"
	// AWSBaseProfileFlag is the AWS base profile name Flag
	AWSBaseProfileFlag string = "aws-base-profile"
	// AWSProfileFlag is the AWS Profile flag
	AWSProfileFlag string = "aws-profile"

	// IAMUserFlag is the IAM User name Flag
	IAMUserFlag string = "iam-user"
	// IAMRoleFlag is the IAM Role name Flag
	IAMRoleFlag string = "iam-role"

	// SourceProfileFlag is the Source Profile Flag
	SourceProfileFlag string = "source-profile"
	// MfaSerialFlag is the MFA Serial Flag
	MfaSerialFlag string = "mfa-serial"

	// OutputFlag is the Output Flag
	OutputFlag string = "output"

	// NoMFAFlag indicates that no MFA device should be configured as one exists
	NoMFAFlag string = "no-mfa"

	// VerboseFlag is the Verbose Flag
	VerboseFlag string = "verbose"
)

func stringSliceContains(stringSlice []string, value string) bool {
	for _, x := range stringSlice {
		if value == x {
			return true
		}
	}
	return false
}

type errInvalidKeychainName struct {
	KeychainName string
}

func (e *errInvalidKeychainName) Error() string {
	return fmt.Sprintf("invalid keychain name '%s'", e.KeychainName)
}

func checkVault(v *viper.Viper) error {
	// Both keychain name and profile are required or both must be missing
	keychainName := v.GetString(VaultAWSKeychainNameFlag)
	keychainNames := []string{
		VaultAWSKeychainNameDefault,
	}
	if len(keychainName) > 0 && !stringSliceContains(keychainNames, keychainName) {
		return fmt.Errorf("%s is invalid, expected %v: %w", VaultAWSKeychainNameFlag, keychainNames, &errInvalidKeychainName{KeychainName: keychainName})
	}

	return nil
}

type errInvalidRegion struct {
	Region string
}

func (e *errInvalidRegion) Error() string {
	return fmt.Sprintf("invalid region %q", e.Region)
}

// Note: Testing the partition is not really the best check here, but its sufficient
func checkRegion(v *viper.Viper) error {

	r := v.GetString(AWSRegionFlag)
	if _, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), r); !ok {
		return fmt.Errorf("%s is invalid: %w", AWSRegionFlag, &errInvalidRegion{Region: r})
	}

	return nil
}

type errInvalidAccountID struct {
	AccountID string
}

func (e *errInvalidAccountID) Error() string {
	return fmt.Sprintf("invalid Account ID %q", e.AccountID)
}

func checkAccountID(id string) error {
	if matched, err := regexp.Match(`^\d{12}$`, []byte(id)); !matched || err != nil {
		return fmt.Errorf("AWS Account ID must be a 12 digit number: %w", &errInvalidAccountID{AccountID: id})
	}

	return nil
}

type errInvalidProfileName struct {
	ProfileName string
}

func (e *errInvalidProfileName) Error() string {
	return fmt.Sprintf("invalid Account ID %q", e.ProfileName)
}

func checkProfileName(profileName string) error {
	if matched, err := regexp.Match(`[A-Za-z0-9\-\_]+`, []byte(profileName)); !matched || err != nil {
		return fmt.Errorf("AWS Profile Name must be can only contain letters, numbers, hyphens, and underscores: %w", &errInvalidProfileName{ProfileName: profileName})
	}

	return nil
}

type errInvalidProfileAccount struct {
	ProfileAccount string
}

func (e *errInvalidProfileAccount) Error() string {
	return fmt.Sprintf("invalid Profile Name and Account ID %q", e.ProfileAccount)
}

func checkProfileAccount(v *viper.Viper) error {
	profileAccounts := v.GetStringSlice(AWSProfileAccountFlag)
	for _, profileAccount := range profileAccounts {
		// Validate the profile name and account are separated by a colon
		if !strings.Contains(profileAccount, ":") {
			return fmt.Errorf("Each Profile Name and Account ID must be separated by a colon ':': %w", &errInvalidProfileAccount{ProfileAccount: profileAccount})
		}
		// Split out the profile name and account ID
		profileAccountParts := strings.Split(profileAccount, ":")
		profileName := profileAccountParts[0]
		accountID := profileAccountParts[1]

		if err := checkProfileName(profileName); err != nil {
			return err
		}
		if err := checkAccountID(accountID); err != nil {
			return err
		}
	}
	return nil
}

type errInvalidIAMUser struct {
	IAMUser string
}

func (e *errInvalidIAMUser) Error() string {
	return fmt.Sprintf("invalid output %q", e.IAMUser)
}

func checkIAMUser(v *viper.Viper) error {

	user := v.GetString(IAMUserFlag)
	if len(user) == 0 {
		return fmt.Errorf("%s is invalid: %w", IAMUserFlag, &errInvalidIAMUser{IAMUser: user})
	}

	return nil
}

type errInvalidIAMRole struct {
	IAMRole string
}

func (e *errInvalidIAMRole) Error() string {
	return fmt.Sprintf("invalid output %q", e.IAMRole)
}

func checkIAMRole(v *viper.Viper) error {

	role := v.GetString(IAMRoleFlag)
	if len(role) == 0 {
		return fmt.Errorf("%s is invalid: %w", IAMRoleFlag, &errInvalidIAMRole{IAMRole: role})
	}

	return nil
}

type errInvalidOutput struct {
	Output string
}

func (e *errInvalidOutput) Error() string {
	return fmt.Sprintf("invalid output %q", e.Output)
}

func checkOutput(v *viper.Viper) error {

	o := v.GetString(OutputFlag)
	outputTypes := []string{
		"text",
		"json",
		"yaml",
		"table",
	}
	if len(o) > 0 && !stringSliceContains(outputTypes, o) {
		return fmt.Errorf("%s is invalid, expected one of %v: %w", OutputFlag, outputTypes, &errInvalidOutput{Output: o})
	}

	return nil
}
