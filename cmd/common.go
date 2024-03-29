package main

import (
	"fmt"
	"log"
	"os"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/pkg/browser"
	"github.com/skip2/go-qrcode"
	"gopkg.in/ini.v1"
)

const maxMFATokenPromptAttempts = 5

var globalMFACodeMap = make(map[string]string)

func promptMFAtoken(messagePrefix string, logger *log.Logger) string {
	var token string
	for attempts := maxMFATokenPromptAttempts; token == "" && attempts > 0; attempts-- {
		t, err := prompt.TerminalPrompt(fmt.Sprintf("%sMFA token (%d attempts remaining): ", messagePrefix, attempts))
		if err != nil {
			logger.Println(err)
			continue
		}
		err = validate.Var(t, "numeric,len=6")
		if err != nil {
			logger.Println("MFA token must be 6 digits. Please try again.")
			continue
		}

		if _, found := globalMFACodeMap[t]; found {
			logger.Println("MFA token has already been used. Please try again.")
			continue
		}
		globalMFACodeMap[t] = t
		token = t
	}
	return token
}

func getMFATokenPair(logger *log.Logger) MFATokenPair {
	var mfaTokenPair MFATokenPair
	for attempts := maxMFATokenPromptAttempts; attempts > 0; attempts-- {
		logger.Printf("Two unique MFA tokens needed to activate MFA device (%d attempts remaining)\n", attempts)
		authToken1 := promptMFAtoken("First ", logger)
		authToken2 := promptMFAtoken("Second ", logger)

		mfaTokenPair = MFATokenPair{
			Token1: authToken1,
			Token2: authToken2,
		}
		err := validate.Struct(mfaTokenPair)
		if err != nil {
			logger.Println(err)
		} else {
			break
		}
	}
	return mfaTokenPair
}

// DefaultConfig is the standard config struct for managing subcommand input
type DefaultConfig struct {
	Logger *log.Logger
	Config *vault.ConfigFile

	IAMUser   string
	IAMRole   string
	Partition string
	Region    string
	Output    string

	AWSProfileAccounts []string
	AWSProfiles        []vault.ProfileSection
	MFASerial          string
}

// UpdateAWSProfile updates or creates a single AWS profile to the AWS config file
func (dc *DefaultConfig) UpdateAWSProfile(iniFile *ini.File, profile *vault.ProfileSection, sourceProfile *string) error {
	dc.Logger.Printf("Adding the profile %q to the AWS config file", profile.Name)

	sectionName := fmt.Sprintf("profile %s", profile.Name)

	// Get or create section before updating
	var err error
	var section *ini.Section
	section = iniFile.Section(sectionName)
	if section == nil {
		section, err = iniFile.NewSection(sectionName)
		if err != nil {
			return fmt.Errorf("error creating section %q: %w", profile.Name, err)
		}
	}

	// Add the source profile when provided
	if sourceProfile != nil {
		_, err = section.NewKey("source_profile", *sourceProfile)
		if err != nil {
			return fmt.Errorf("unable to add source profile: %w", err)
		}
	}

	if err = section.ReflectFrom(&profile); err != nil {
		return fmt.Errorf("error mapping profile to ini file: %w", err)
	}
	_, err = section.NewKey("output", dc.Output)
	if err != nil {
		return fmt.Errorf("unable to add output key: %w", err)
	}
	return nil
}

func getKeyring(keychainName string) (*keyring.Keyring, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "aws-vault",
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.FileBackend,
		},
		KeychainName:             keychainName,
		KeychainTrustApplication: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error opening keyring: %w", err)
	}

	return &ring, nil
}

func generateQrCode(payload string, tempFile *os.File) error {
	// Creates QR Code
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("unable to create qr code: %w", err)
	}

	// Generates a QR PNG 256 x 256, returns []byte
	qr, err := q.PNG(256)
	if err != nil {
		return fmt.Errorf("unable to generate PNG: %w", err)
	}

	// Write the QR PNG to the Temp File
	if _, err := tempFile.Write(qr); err != nil {
		_ = tempFile.Close()
		return err
	}
	return nil
}

func openQrCode(tempFile *os.File) error {
	err := browser.OpenFile(tempFile.Name())
	if err != nil {
		return fmt.Errorf("unable to open QR Code PNG: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("unable to close QR Code: %w", err)
	}
	return nil
}

func getPartition(region string) (string, error) {
	partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !ok {
		return "", fmt.Errorf("Error finding partition for region: %s", region)
	}
	return partition.ID(), nil
}
