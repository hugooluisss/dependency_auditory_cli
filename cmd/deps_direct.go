package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newDepsDirectCommand() *cobra.Command {
	var includeDev bool

	cmd := &cobra.Command{
		Use:   "direct",
		Short: "List direct dependencies from composer.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := filesystem.NewReader()
			composerParser := parser.NewComposerJSONParser()
			uc := usecase.NewListDirectDependenciesUseCase(reader, composerParser)

			result, err := uc.Execute(projectPath, includeDev)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}

	cmd.Flags().BoolVar(&includeDev, "include-dev", false, "Include require-dev dependencies")
	return cmd
}
