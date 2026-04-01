package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newDetectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Detect the ecosystem of a project at --path",
		RunE: func(cmd *cobra.Command, args []string) error {
			uc := usecase.NewDetectProjectUseCase(newRegistry())
			result, err := uc.Execute(projectPath)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}
}
