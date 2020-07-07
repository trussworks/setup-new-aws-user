package main

import (
	"log"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/assert"
)

func TestAddProfile(t *testing.T) {

	// Test logger
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.SetFlags(0)

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

	f := newConfigFile(t, defaultConfigAddProfile)
	defer func() {
		errRemove := os.Remove(f)
		assert.NoError(t, errRemove)
	}()

	config, err := vault.LoadConfig(f)
	assert.NoError(t, err)

	mfaSerial := "arn:aws:iam::111111111111:mfa/test-user"
	addProfileConfig := AddProfileConfig{
		// Config
		Logger: logger,
		Config: config,

		// Profile Inputs
		IAMRole:   "test-role",
		Region:    "us-west-2",
		Partition: "aws",
		Output:    "json",

		// Profiles
		AWSProfileAccounts: []string{"test-id-new:123456789012"},
		AWSProfileName:     "test-id",
	}
	err = addProfileConfig.AddProfile()
	assert.NoError(t, err)

	// re-load the config file
	config, err = vault.LoadConfig(f)
	assert.NoError(t, err)

	testSection, ok := config.ProfileSection("test-id-new")
	assert.True(t, ok)
	assert.Equal(t, testSection.SourceProfile, "test-id-base")
	assert.Equal(t, testSection.MfaSerial, mfaSerial)
	assert.Equal(t, testSection.RoleARN, "arn:aws:iam::123456789012:role/test-role")
	assert.Equal(t, testSection.Region, "us-west-2")
	// assert.Equal(t, testBaseSection.Output, "json")
}
