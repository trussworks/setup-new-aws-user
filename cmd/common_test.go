package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
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

type commonTestSuite struct {
	suite.Suite
}

func TestCommonSuite(t *testing.T) {
	suite.Run(t, &commonTestSuite{})
}

func (suite *commonTestSuite) TestGenerateQrCode() {
	tempFile, err := ioutil.TempFile("", "temp-qr.*.png")
	suite.NoError(err)
	defer func() {
		errRemove := os.Remove(tempFile.Name())
		suite.NoError(errRemove)
	}()

	err = generateQrCode("otpauth://totp/super@top?secret=secret", tempFile)
	suite.NoError(err)
}

func (suite *commonTestSuite) TestGetPartition() {
	commPartition, err := getPartition("us-west-2")
	suite.Equal(commPartition, "aws")
	suite.NoError(err)

	govPartition, err := getPartition("us-gov-west-1")
	suite.Equal(govPartition, "aws-us-gov")
	suite.NoError(err)

	_, err = getPartition("aws-under-the-sea")
	suite.Error(err)
}
