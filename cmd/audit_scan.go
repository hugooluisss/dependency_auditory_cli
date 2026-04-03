package cmd

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/usecase"
	"github.com/spf13/cobra"
)

func newAuditScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies for risk signals and known vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			uc := usecase.NewAuditScanUseCase(newRegistry())
			result, err := uc.Execute(projectPath)
			if err != nil {
				return err
			}
			return writeSuccessResponse(result)
		},
	}
}
