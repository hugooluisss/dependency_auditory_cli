package cmd

import "github.com/spf13/cobra"

const Version = "0.1.0"

type versionOutput struct {
	Version string `json:"version"`
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeSuccessResponse(versionOutput{Version: Version})
		},
	}
}
