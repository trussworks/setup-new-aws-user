package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is the published version of the utility
var version string

func versionFunction(cmd *cobra.Command, args []string) error {
	if len(version) == 0 {
		fmt.Println("development")
		return nil
	}
	fmt.Println(version)
	return nil
}
