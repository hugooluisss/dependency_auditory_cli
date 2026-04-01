package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newDepsDirectCommand() *cobra.Command {
	var includeDev bool

	cmd := &cobra.Command{
		Use:   "direct",
		Short: "List direct dependencies from the project manifest",
		RunE: func(cmd *cobra.Command, args []string) error {
			uc := usecase.NewListDirectDependenciesUseCase(newRegistry())
			result, err := uc.Execute(projectPath, includeDev)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}

	cmd.Flags().BoolVar(&includeDev, "include-dev", false, "Include dev dependencies")
	return cmd
}
