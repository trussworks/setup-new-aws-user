package main

import (
<<<<<<< HEAD
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
	baseProfile := vault.ProfileSection{
		Name:   "test-base",
		Region: "us-west-2",
	}
	roleProfile := vault.ProfileSection{
		Name:   "test-role",
		Region: "us-west-2",
	}

	config, _ := vault.LoadConfig(f)
	keyring, err := getKeyring("test")
	assert.NoError(t, err)
	setupConfig := SetupConfig{
		Logger:      logger,
		Name:        "test-user",
		BaseProfile: &baseProfile,
		RoleProfile: &roleProfile,
		Output:      "json",
		Config:      config,
		QrTempFile:  nil,
		Keyring:     keyring,
	}
	logger.SetFlags(0)
	err = setupConfig.UpdateAWSConfigFile()
	assert.NoError(t, err)
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
=======
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type commandTestSuite struct {
	suite.Suite
	viper  *viper.Viper
	logger *log.Logger
}

type initFlags func(f *pflag.FlagSet)

func (suite *commandTestSuite) Setup(fn initFlags, flagSet []string) {
	// Disable any logging that isn't attached to the logger unless using the verbose flag
	log.SetOutput(ioutil.Discard)
	log.SetFlags(0)

	// Setup logger
	var logger = log.New(os.Stdout, "", log.LstdFlags)

	// Remove the flags for the logger
	logger.SetFlags(0)
	suite.SetLogger(logger)

	// Setup viper
	suite.viper = nil

	flag := pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
	fn(flag)
	errFlagParse := flag.Parse(flagSet)
	if errFlagParse != nil {
		suite.logger.Fatal(errFlagParse)
	}

	v := viper.New()
	err := v.BindPFlags(flag)
	if err != nil {
		suite.logger.Fatal(fmt.Errorf("could not bind flags: %w", err))
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	suite.SetViper(v)
}

func (suite *commandTestSuite) SetViper(v *viper.Viper) {
	suite.viper = v
}

func (suite *commandTestSuite) SetLogger(logger *log.Logger) {
	suite.logger = logger
}

func TestCommandSuite(t *testing.T) {
	suite.Run(t, &commandTestSuite{})
}

func (suite *commandTestSuite) TestAddProfileFlags() {
	suite.Setup(AddProfileInitFlags, []string{
		"--aws-profile-account", "test-new:012345678901",
		"--iam-user", "me",
		"--iam-role", "engineer",
	})
	suite.NoError(AddProfileCheckConfig(suite.viper))
}

func (suite *commandTestSuite) TestSetupFlags() {
	suite.Setup(SetupUserInitFlags, []string{
		"--aws-profile-account", "test-id:012345678901",
		"--iam-user", "me",
		"--iam-role", "engineer",
	})
	suite.NoError(SetupUserCheckConfig(suite.viper))
>>>>>>> 887956c... Rename test file for setup subcommand
}
