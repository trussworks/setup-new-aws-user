package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/suite"
)

type setupTestSuite struct {
	suite.Suite
	logger *log.Logger
}

func (suite *setupTestSuite) Setup() {
	// Disable any logging that isn't attached to the logger unless using the verbose flag
	log.SetOutput(ioutil.Discard)
	log.SetFlags(0)

	// Setup logger
	var logger = log.New(os.Stdout, "", log.LstdFlags)

	// Remove the flags for the logger
	logger.SetFlags(0)
	suite.SetLogger(logger)
}

func (suite *setupTestSuite) SetLogger(logger *log.Logger) {
	suite.logger = logger
}

func TestSetupSuite(t *testing.T) {
	suite.Run(t, &setupTestSuite{})
}

func (suite *setupTestSuite) TestUpdateAWSConfigFile() {
	suite.Setup()

	var defaultSetupConfig = []byte(`[profile test]
region=us-west-2
output=json
`)

	f := newConfigFile(suite.T(), defaultSetupConfig)
	defer func() {
		errRemove := os.Remove(f)
		suite.NoError(errRemove)
	}()

	config, err := vault.LoadConfig(f)
	suite.NoError(err)

	keyring, err := getKeyring("test")
	suite.NoError(err)

	mfaSerial := "arn:aws:iam::111111111111:mfa/test-user"
	setupConfig := SetupConfig{
		// Config
		QrTempFile: nil,
		Keyring:    keyring,

		// Profiles
		BaseProfileName: "test-id-base",
	}

	// Config
	setupConfig.Logger = suite.logger
	setupConfig.Config = config

	// Profile Inputs
	setupConfig.IAMUser = "test-user"
	setupConfig.IAMRole = "test-role"
	setupConfig.Region = "us-west-2"
	setupConfig.Partition = "aws"
	setupConfig.Output = "json"

	// Profiles
	setupConfig.AWSProfileAccounts = []string{"test-id:123456789012"}
	setupConfig.MFASerial = mfaSerial

	// Update the AWS Config for the test
	err = setupConfig.UpdateAWSConfigFile()
	suite.NoError(err)

	// re-load the config file
	config, err = vault.LoadConfig(f)
	suite.NoError(err)

	testBaseSection, ok := config.ProfileSection("test-id-base")
	suite.True(ok)
	suite.Equal(testBaseSection.MfaSerial, mfaSerial)
	suite.Equal(testBaseSection.Region, "us-west-2")
	// suite.Equal(testBaseSection.Output, "json")

	testSection, ok := config.ProfileSection("test-id")
	suite.True(ok)
	suite.Equal(testSection.SourceProfile, "test-id-base")
	suite.Equal(testSection.MfaSerial, mfaSerial)
	suite.Equal(testSection.RoleARN, "arn:aws:iam::123456789012:role/test-role")
	suite.Equal(testSection.Region, "us-west-2")
	// suite.Equal(testBaseSection.Output, "json")
}
