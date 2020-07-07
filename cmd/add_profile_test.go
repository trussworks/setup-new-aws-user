package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/suite"
)

type addProfileTestSuite struct {
	suite.Suite
	logger *log.Logger
}

func (suite *addProfileTestSuite) Setup() {
	// Disable any logging that isn't attached to the logger unless using the verbose flag
	log.SetOutput(ioutil.Discard)
	log.SetFlags(0)

	// Setup logger
	var logger = log.New(os.Stdout, "", log.LstdFlags)

	// Remove the flags for the logger
	logger.SetFlags(0)
	suite.SetLogger(logger)
}

func (suite *addProfileTestSuite) SetLogger(logger *log.Logger) {
	suite.logger = logger
}

func TestAddProfileSuite(t *testing.T) {
	suite.Run(t, &addProfileTestSuite{})
}

func (suite *addProfileTestSuite) TestAddProfile() {
	suite.Setup()

	var defaultConfigAddProfile = []byte(`[profile test-id-base]
region=us-west-2
output=json

[profile test-id]
source_profile=test-id-base
mfa_serial=arn:aws:iam::111111111111:mfa/test-user
role_arn=arn:aws:iam::222222222222:role/engineer
region=us-west-2
output=json
`)

	f := newConfigFile(suite.T(), defaultConfigAddProfile)
	defer func() {
		errRemove := os.Remove(f)
		suite.NoError(errRemove)
	}()

	config, err := vault.LoadConfig(f)
	suite.NoError(err)

	mfaSerial := "arn:aws:iam::111111111111:mfa/test-user"
	addProfileConfig := AddProfileConfig{
		AWSProfileName: "test-id",
	}

	// Config
	addProfileConfig.Logger = suite.logger
	addProfileConfig.Config = config

	// Profile Inputs
	addProfileConfig.IAMUser = ""
	addProfileConfig.IAMRole = "test-role"
	addProfileConfig.Region = "us-west-2"
	addProfileConfig.Partition = "aws"
	addProfileConfig.Output = "json"

	// Profiles
	addProfileConfig.AWSProfileAccounts = []string{"test-id-new:123456789012"}
	addProfileConfig.MFASerial = mfaSerial

	// Add the profile
	err = addProfileConfig.AddProfile()
	suite.NoError(err)

	// re-load the config file
	config, err = vault.LoadConfig(f)
	suite.NoError(err)

	testSection, ok := config.ProfileSection("test-id-new")
	suite.True(ok)
	suite.Equal(testSection.SourceProfile, "test-id-base")
	suite.Equal(testSection.MfaSerial, mfaSerial)
	suite.Equal(testSection.RoleARN, "arn:aws:iam::123456789012:role/test-role")
	suite.Equal(testSection.Region, "us-west-2")
	// suite.Equal(testBaseSection.Outpu"json")
}
