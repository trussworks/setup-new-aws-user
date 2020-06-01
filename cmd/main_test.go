package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/stretchr/testify/assert"
)

var defaultConfig = []byte(`[profile test]
region=us-west-2
output=json
`)

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

func TestExistingAWSProfile(t *testing.T) {
	f := newConfigFile(t, defaultConfig)
	defer os.Remove(f)
	config, _ := vault.LoadConfig(f)
	baseProfile := vault.Profile{
		Name:   "test",
		Region: "us-west-2",
	}
	keyring, err := getKeyring("test")
	assert.NoError(t, err)
	user := User{
		Name:        "test",
		BaseProfile: &baseProfile,
		Output:      "json",
		Config:      config,
		QrTempFile:  nil,
		Keyring:     keyring,
	}

	err = checkExistingAWSProfile(baseProfile.Name, user.Config)
	assert.Error(t, err)
	err = checkExistingAWSProfile("missing", user.Config)
	assert.NoError(t, err)
}

func TestUpdateAWSConfigFile(t *testing.T) {
	f := newConfigFile(t, defaultConfig)
	defer os.Remove(f)
	baseProfile := vault.Profile{
		Name:   "test-base",
		Region: "us-west-2",
	}
	roleProfile := vault.Profile{
		Name:   "test-role",
		Region: "us-west-2",
	}

	config, _ := vault.LoadConfig(f)
	keyring, err := getKeyring("test")
	assert.NoError(t, err)
	user := User{
		Name:        "test-user",
		BaseProfile: &baseProfile,
		RoleProfile: &roleProfile,
		Output:      "json",
		Config:      config,
		QrTempFile:  nil,
		Keyring:     keyring,
	}
	err = user.UpdateAWSConfigFile()
	assert.NoError(t, err)
}

func TestGenerateQrCode(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "temp-qr.*.png")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

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
