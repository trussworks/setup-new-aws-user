package main

import (
	"io"
	"log"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type cliTestSuite struct {
	suite.Suite
	viper  *viper.Viper
	logger *log.Logger
}

func (suite *cliTestSuite) Setup() {
	// Disable any logging that isn't attached to the logger unless using the verbose flag
	log.SetOutput(io.Discard)
	log.SetFlags(0)

	// Setup logger
	var logger = log.New(os.Stdout, "", log.LstdFlags)

	// Remove the flags for the logger
	logger.SetFlags(0)
	suite.SetLogger(logger)

	// Setup viper
	v := viper.New()
	suite.SetViper(v)
}

func (suite *cliTestSuite) SetViper(v *viper.Viper) {
	suite.viper = v
}

func (suite *cliTestSuite) SetLogger(logger *log.Logger) {
	suite.logger = logger
}

func TestCLISuite(t *testing.T) {
	suite.Run(t, &cliTestSuite{})
}

func (suite *cliTestSuite) TestStringSliceContains() {
	suite.True(stringSliceContains([]string{"hello", "world"}, "hello"))
	suite.False(stringSliceContains([]string{"hello", "world"}, "planet"))
}

func (suite *cliTestSuite) TestCheckVault() {
	suite.Setup()

	testValues := []string{
		"",
		VaultAWSKeychainNameDefault,
	}
	for _, testValue := range testValues {
		suite.viper.Set(VaultAWSKeychainNameFlag, testValue)
		suite.viper.Set(AWSProfileFlag, "profile")
		suite.NoError(checkVault(suite.viper))
	}
	testValuesWithErrors := []string{
		"AnyOtherKeychainName",
	}
	for _, testValue := range testValuesWithErrors {
		suite.viper.Set(VaultAWSKeychainNameFlag, testValue)
		suite.viper.Set(AWSProfileFlag, "profile")
		suite.Error(checkVault(suite.viper))
	}
}

func (suite *cliTestSuite) TestCheckRegion() {
	suite.Setup()

	testValues := []string{
		endpoints.UsEast1RegionID,
		endpoints.UsEast2RegionID,
		endpoints.UsWest1RegionID,
		endpoints.UsWest2RegionID,
	}
	for _, testValue := range testValues {
		suite.viper.Set(AWSRegionFlag, testValue)
		suite.NoError(checkRegion(suite.viper))
	}
	testValuesWithErrors := []string{
		"AnyOtherRegionName",
	}
	for _, testValue := range testValuesWithErrors {
		suite.viper.Set(AWSRegionFlag, testValue)
		suite.Error(checkRegion(suite.viper))
	}
}

func (suite *cliTestSuite) TestCheckProfileName() {
	suite.Setup()
	testValues := []string{
		"test-id",
		"test-id1",
		"test-id_1",
	}
	for _, testValue := range testValues {
		suite.NoError(checkProfileName(testValue))
	}
	testValuesWithErrors := []string{
		"",
	}
	for _, testValue := range testValuesWithErrors {
		suite.Error(checkProfileName(testValue))
	}
}

func (suite *cliTestSuite) TestCheckAccountID() {
	suite.Setup()
	testValues := []string{
		"012345678901",
		"123456789012",
	}
	for _, testValue := range testValues {
		suite.NoError(checkAccountID(testValue))
	}
	testValuesWithErrors := []string{
		"",
		"12345678901",
		"1234567890123",
	}
	for _, testValue := range testValuesWithErrors {
		suite.Error(checkAccountID(testValue))
	}
}

func (suite *cliTestSuite) TestCheckProfileAccount() {
	suite.Setup()

	testValues := [][]string{
		{"test-id:012345678901"},
		{"test-id1:012345678901", "test-id2:012345678901", "test-id3:012345678901"},
	}
	for _, testValue := range testValues {
		suite.viper.Set(AWSProfileAccountFlag, testValue)
		err := checkProfileAccount(suite.viper)
		suite.NoError(err)
	}
	testValuesWithErrors := [][]string{
		{"test-id:0123456789011"},
		{":012345678901"},
		{"test-id:"},
		{"test-id012345678901"},
	}
	for _, testValue := range testValuesWithErrors {
		suite.viper.Set(AWSProfileAccountFlag, testValue)
		err := checkProfileAccount(suite.viper)
		suite.Error(err)
	}
}

func (suite *cliTestSuite) TestCheckIAMUser() {
	suite.Setup()

	testValues := []string{
		"test",
	}
	for _, testValue := range testValues {
		suite.viper.Set(IAMUserFlag, testValue)
		suite.NoError(checkIAMUser(suite.viper))
	}
	testValuesWithErrors := []string{
		"",
	}
	for _, testValue := range testValuesWithErrors {
		suite.viper.Set(IAMUserFlag, testValue)
		suite.Error(checkIAMUser(suite.viper))
	}
}

func (suite *cliTestSuite) TestCheckIAMRole() {
	suite.Setup()

	testValues := []string{
		"test",
	}
	for _, testValue := range testValues {
		suite.viper.Set(IAMRoleFlag, testValue)
		suite.NoError(checkIAMRole(suite.viper))
	}
	testValuesWithErrors := []string{
		"",
	}
	for _, testValue := range testValuesWithErrors {
		suite.viper.Set(IAMRoleFlag, testValue)
		suite.Error(checkIAMRole(suite.viper))
	}
}

func (suite *cliTestSuite) TestCheckOutput() {
	suite.Setup()

	testValues := []string{
		"text",
		"json",
		"yaml",
		"table",
	}
	for _, testValue := range testValues {
		suite.viper.Set(OutputFlag, testValue)
		suite.NoError(checkOutput(suite.viper))
	}
	testValuesWithErrors := []string{
		"bad",
	}
	for _, testValue := range testValuesWithErrors {
		suite.viper.Set(OutputFlag, testValue)
		suite.Error(checkOutput(suite.viper))
	}
}
