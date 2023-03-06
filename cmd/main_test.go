package main

import (
	"fmt"
	"io"
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
	log.SetOutput(io.Discard)
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
		"--aws-profile", "test-id",
		"--aws-profile-account", "test-new:012345678901",
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
}
