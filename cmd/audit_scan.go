package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newAuditScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan for suspicious dependency risk signals (offline heuristics)",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := filesystem.NewReader()
			composerJSONParser := parser.NewComposerJSONParser()
			composerLockParser := parser.NewComposerLockParser()

			uc := usecase.NewAuditScanUseCase(reader, composerJSONParser, composerLockParser)
			result, err := uc.Execute(projectPath)
			if err != nil {
				return err
			}

			return writeSuccessResponse(result)
		},
	}
}
