package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := cobra.Command{
		Use:   "setup-new-aws-user [flags]",
		Short: "Setup new AWS user with aws-vault",
		Long:  "Setup new AWS user with aws-vault",
	}

	completionCommand := &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long:  "To install completion scripts run:\nsetup-new-aws-user completion > /usr/local/etc/bash_completion.d/setup-new-aws-user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(os.Stdout)
		},
	}
	root.AddCommand(completionCommand)

	setupUserCommand := &cobra.Command{
		Use:                   "setup [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Setup new AWS user with aws-vault",
		Long:                  "Setup new AWS user with aws-vault",
		RunE:                  setupUserFunction,
	}
	SetupUserInitFlags(setupUserCommand.Flags())
	root.AddCommand(setupUserCommand)

	addProfileCommand := &cobra.Command{
		Use:                   "add-profile [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Add new AWS config profile",
		Long:                  "Add new AWS config profile",
		RunE:                  addProfileFunction,
	}
	AddProfileInitFlags(addProfileCommand.Flags())
	root.AddCommand(addProfileCommand)

	versionCommand := &cobra.Command{
		Use:                   "version",
		DisableFlagsInUseLine: true,
		Short:                 "Print the version",
		Long:                  "Print the version",
		RunE:                  versionFunction,
	}
	root.AddCommand(versionCommand)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
