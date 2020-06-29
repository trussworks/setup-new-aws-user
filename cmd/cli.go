package main

import (
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/spf13/viper"
)

const (
	// AWSRegionFlag is the generic AWS Region Flag
	AWSRegionFlag string = "aws-region"
	// AWSAccountIDFlag is the AWS AccountID Flag
	AWSAccountIDFlag string = "aws-account-id"

	// VaultAWSKeychainNameFlag is the aws-vault keychain name Flag
	VaultAWSKeychainNameFlag string = "aws-vault-keychain-name"
	// VaultAWSKeychainNameDefault is the aws-vault default keychain name
	VaultAWSKeychainNameDefault string = "login"
	// VaultAWSProfileFlag is the aws-vault profile name Flag
	VaultAWSProfileFlag string = "aws-profile"

	// IAMUserFlag is the IAM User name Flag
	IAMUserFlag string = "iam-user"
	// IAMRoleFlag is the IAM Role name Flag
	IAMRoleFlag string = "iam-role"

	// OutputFlag is the Output Flag
	OutputFlag = "output"

	// VerboseFlag is the Verbose Flag
	VerboseFlag string = "debug-logging"
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

type errInvalidAWSProfile struct {
	Profile string
}

func (e *errInvalidAWSProfile) Error() string {
	return fmt.Sprintf("invalid aws profile '%s'", e.Profile)
}

type errInvalidVault struct {
	KeychainName string
	Profile      string
}

func (e *errInvalidVault) Error() string {
	return fmt.Sprintf("invalid keychain name %q or profile %q", e.KeychainName, e.Profile)
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

	awsProfile := v.GetString(VaultAWSProfileFlag)
	if len(awsProfile) == 0 {
		return fmt.Errorf("%s must not be empty: %w", VaultAWSProfileFlag, &errInvalidAWSProfile{Profile: awsProfile})
	}

	return nil
}

type errInvalidRegion struct {
	Region string
}

func (e *errInvalidRegion) Error() string {
	return fmt.Sprintf("invalid region %q", e.Region)
}

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

func checkAccountID(v *viper.Viper) error {
	id := v.GetString(AWSAccountIDFlag)
	if matched, err := regexp.Match(`\d[12]`, []byte(id)); !matched || err != nil {
		return fmt.Errorf("%s must be a 12 digit number: %w", AWSAccountIDFlag, &errInvalidAccountID{AccountID: id})
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
