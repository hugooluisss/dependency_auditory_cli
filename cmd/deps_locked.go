package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newDepsLockedCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "locked",
		Short: "List locked dependencies from composer.lock",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := filesystem.NewReader()
			lockParser := parser.NewComposerLockParser()
			uc := usecase.NewListLockedDependenciesUseCase(reader, lockParser)

			result, err := uc.Execute(projectPath)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}
}
