package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hugooluisss/dependency_auditory_cli/internal/advisory/osv"
	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
	ecosystemcomposer "github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem/composer"
	ecosystemgomod "github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem/gomod"
	ecosystemnpm "github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem/npm"
	ecosystempython "github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem/python"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	projectPath  string
	outputFormat string
	offline      bool
	jsonWriter   = output.NewJSONWriter(os.Stdout)
)

var rootCmd = &cobra.Command{
	Use:           "depguard",
	Short:         "depguard inspects dependencies as AI-ready JSON",
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
	rootCmd.PersistentFlags().BoolVar(&offline, "offline", false, "Disable remote vulnerability lookups")

	rootCmd.AddCommand(newDetectCommand())
	rootCmd.AddCommand(newDepsCommand())
	rootCmd.AddCommand(newAuditCommand())
	rootCmd.AddCommand(newVersionCommand())
}

// newRegistry is the single registration point for ecosystem scanners.
// To add support for a new ecosystem, add its scanner here:
//
//	npm.NewScanner(reader)
//	gomod.NewScanner(reader)
func newRegistry() *ecosystem.Registry {
	reader := filesystem.NewReader()
	var vulnerabilityClient ecosystem.VulnerabilitySource
	if !offline {
		vulnerabilityClient = osv.NewClient(&http.Client{Timeout: 12 * time.Second})
	}
	return ecosystem.NewRegistry(
		ecosystemcomposer.NewScanner(reader, vulnerabilityClient),
		ecosystemnpm.NewScanner(reader, vulnerabilityClient),
		ecosystemgomod.NewScanner(reader, vulnerabilityClient),
		ecosystempython.NewScanner(reader, vulnerabilityClient),
	)
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
