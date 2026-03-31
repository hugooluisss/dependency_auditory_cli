package cmd

import (
	"fmt"
	"os"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	projectPath  string
	outputFormat string
	jsonWriter   = output.NewJSONWriter(os.Stdout)
)

var rootCmd = &cobra.Command{
	Use:           "depguard",
	Short:         "depguard inspects Composer dependencies as AI-ready JSON",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if outputFormat != "json" {
			return domain.NewAppError(domain.CodeUnsupportedFormat, "Only json output format is supported in this version", nil)
		}
		return nil
	},
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return writeErrorResponse(err)
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&projectPath, "path", ".", "Target project path")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "format", "json", "Output format")

	rootCmd.AddCommand(newDetectCommand())
	rootCmd.AddCommand(newDepsCommand())
	rootCmd.AddCommand(newAuditCommand())
	rootCmd.AddCommand(newVersionCommand())
}

func writeSuccessResponse(data any) error {
	return jsonWriter.Write(domain.EnvelopeResponse{
		OK:    true,
		Data:  data,
		Error: nil,
	})
}

func writeErrorResponse(err error) error {
	cliErr := domain.ToCLIError(err)
	if writeErr := jsonWriter.Write(domain.EnvelopeResponse{
		OK:    false,
		Data:  nil,
		Error: cliErr,
	}); writeErr != nil {
		fmt.Fprintln(os.Stderr, writeErr.Error())
	}

	fmt.Fprintln(os.Stderr, err.Error())
	return err
}
