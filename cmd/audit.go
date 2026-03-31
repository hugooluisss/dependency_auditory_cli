package cmd

import "github.com/spf13/cobra"

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run local dependency audit checks",
	}

	cmd.AddCommand(newAuditScanCommand())
	return cmd
}
