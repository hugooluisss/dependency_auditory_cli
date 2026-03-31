package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newDetectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Detect if a path is a Composer project",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := filesystem.NewReader()
			uc := usecase.NewDetectProjectUseCase(reader)

			result, err := uc.Execute(projectPath)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}
}
