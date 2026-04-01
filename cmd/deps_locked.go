package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newDepsLockedCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "locked",
		Short: "List locked dependencies from the project lockfile",
		RunE: func(cmd *cobra.Command, args []string) error {
			uc := usecase.NewListLockedDependenciesUseCase(newRegistry())
			result, err := uc.Execute(projectPath)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}
}
