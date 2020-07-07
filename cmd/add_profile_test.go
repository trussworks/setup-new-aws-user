package main

import (
	"log"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/assert"
)

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

func TestAddProfile(t *testing.T) {

	// Test logger
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.SetFlags(0)

	f := newConfigFile(t, defaultConfigAddProfile)
	defer func() {
		errRemove := os.Remove(f)
		assert.NoError(t, errRemove)
	}()

	config, err := vault.LoadConfig(f)
	assert.NoError(t, err)

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
		AWSProfileAccounts: []string{"test-id:123456789012"},
		AWSProfileName:     "test-id",
	}
	err = addProfileConfig.AddProfile()
	assert.NoError(t, err)

	// TODO: Check contents of file
}
