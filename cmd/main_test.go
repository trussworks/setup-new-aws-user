package main

import (
	"fmt"
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
	profile := vault.Profile{
		Name: "test",
		RoleARN: fmt.Sprintf("arn:aws:iam::%v:role/%v",
			"123456789", "engineer"),
		Region: "us-west-2",
	}
	keyring, err := getKeyring("test")
	assert.NoError(t, err)
	user := User{
		Name:       "test",
		Profile:    &profile,
		Output:     "json",
		Config:     config,
		QRTempFile: nil,
		Keyring:    keyring,
	}

	err = checkExistingAWSProfile(profile.Name, user.Config)
	assert.Error(t, err)
	err = checkExistingAWSProfile("missing", user.Config)
	assert.NoError(t, err)
}

func TestPrintQRCode(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "temp-qr.*.png")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	err = printQRCode("otpauth://totp/super@top?secret=secret", tempFile)
	assert.NoError(t, err)
}
