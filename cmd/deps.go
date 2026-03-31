package cmd

import "github.com/spf13/cobra"

func newDepsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deps",
		Short: "List Composer dependencies",
	}

	cmd.AddCommand(newDepsDirectCommand())
	cmd.AddCommand(newDepsLockedCommand())

	return cmd
}
