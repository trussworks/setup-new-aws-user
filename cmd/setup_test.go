package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/assert"
)

// Test logger
var logger = log.New(os.Stdout, "", log.LstdFlags)

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

	var defaultConfig = []byte(`[profile test]
region=us-west-2
output=json
`)
	f := newConfigFile(t, defaultConfig)
	defer func() {
		errRemove := os.Remove(f)
		assert.NoError(t, errRemove)
	}()

	config, err := vault.LoadConfig(f)
	assert.NoError(t, err)

	keyring, err := getKeyring("test")
	assert.NoError(t, err)

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
	}
	err = setupConfig.UpdateAWSConfigFile()
	assert.NoError(t, err)

	// TODO: Check contents of file
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
