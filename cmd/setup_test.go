package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/assert"
)

func newConfigFile(t *testing.T, b []byte) string {
	f, err := ioutil.TempFile("", "aws-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(f.Name(), b, 0600); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestUpdateAWSConfigFile(t *testing.T) {

	// Test logger
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.SetFlags(0)

	var defaultSetupConfig = []byte(`[profile test]
region=us-west-2
output=json
`)

	f := newConfigFile(t, defaultSetupConfig)
	defer func() {
		errRemove := os.Remove(f)
		assert.NoError(t, errRemove)
	}()

	config, err := vault.LoadConfig(f)
	assert.NoError(t, err)

	keyring, err := getKeyring("test")
	assert.NoError(t, err)

	mfaSerial := "arn:aws:iam::111111111111:mfa/test-user"
	setupConfig := SetupConfig{
		// Config
		Logger:     logger,
		Config:     config,
		QrTempFile: nil,
		Keyring:    keyring,

		// Profile Inputs
		IAMUser:   "test-user",
		IAMRole:   "test-role",
		Region:    "us-west-2",
		Partition: "aws",
		Output:    "json",

		// Profiles
		BaseProfileName:    "test-id-base",
		AWSProfileAccounts: []string{"test-id:123456789012"},
		MFASerial:          mfaSerial,
	}
	err = setupConfig.UpdateAWSConfigFile()
	assert.NoError(t, err)

	// re-load the config file
	config, err = vault.LoadConfig(f)
	assert.NoError(t, err)

	testBaseSection, ok := config.ProfileSection("test-id-base")
	assert.True(t, ok)
	assert.Equal(t, len(testBaseSection.MfaSerial), 0)
	assert.Equal(t, testBaseSection.Region, "us-west-2")
	// assert.Equal(t, testBaseSection.Output, "json")

	testSection, ok := config.ProfileSection("test-id")
	assert.True(t, ok)
	assert.Equal(t, testSection.SourceProfile, "test-id-base")
	assert.Equal(t, testSection.MfaSerial, mfaSerial)
	assert.Equal(t, testSection.RoleARN, "arn:aws:iam::123456789012:role/test-role")
	assert.Equal(t, testSection.Region, "us-west-2")
	// assert.Equal(t, testBaseSection.Output, "json")
}

func TestGenerateQrCode(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "temp-qr.*.png")
	assert.NoError(t, err)
	defer func() {
		errRemove := os.Remove(tempFile.Name())
		assert.NoError(t, errRemove)
	}()

	err = generateQrCode("otpauth://totp/super@top?secret=secret", tempFile)
	assert.NoError(t, err)
}

func TestGetPartition(t *testing.T) {
	commPartition, err := getPartition("us-west-2")
	assert.Equal(t, commPartition, "aws")
	assert.NoError(t, err)

	govPartition, err := getPartition("us-gov-west-1")
	assert.Equal(t, govPartition, "aws-us-gov")
	assert.NoError(t, err)

	_, err = getPartition("aws-under-the-sea")
	assert.Error(t, err)
}
