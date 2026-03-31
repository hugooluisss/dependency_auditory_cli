package usecase

import (
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

type AuditScanUseCase struct {
	reader             *filesystem.Reader
	composerJSONParser *parser.ComposerJSONParser
	composerLockParser *parser.ComposerLockParser
}

func NewAuditScanUseCase(
	reader *filesystem.Reader,
	composerJSONParser *parser.ComposerJSONParser,
	composerLockParser *parser.ComposerLockParser,
) *AuditScanUseCase {
	return &AuditScanUseCase{
		reader:             reader,
		composerJSONParser: composerJSONParser,
		composerLockParser: composerLockParser,
	}
}

func (u *AuditScanUseCase) Execute(projectPath string) (*domain.AuditScanResult, error) {
	resolvedPath, err := u.reader.ResolvePath(projectPath)
	if err != nil {
		return nil, err
	}

	composerJSONPath := filepath.Join(resolvedPath, "composer.json")
	composerLockPath := filepath.Join(resolvedPath, "composer.lock")

	hasComposerJSON, err := u.reader.FileExists(composerJSONPath)
	if err != nil {
		return nil, err
	}
	if !hasComposerJSON {
		return nil, domain.NewAppError(
			domain.CodeProjectNotSupported,
			"No composer.json file was found in the target path",
			nil,
		)
	}

	rawComposerJSON, err := u.reader.ReadFile(composerJSONPath)
	if err != nil {
		return nil, err
	}

	manifest, err := u.composerJSONParser.Parse(rawComposerJSON)
	if err != nil {
		return nil, err
	}

	hasLockfile, err := u.reader.FileExists(composerLockPath)
	if err != nil {
		return nil, err
	}

	findings := u.composerJSONParser.BuildAuditFindings(manifest, hasLockfile)

	if hasLockfile {
		rawComposerLock, readErr := u.reader.ReadFile(composerLockPath)
		if readErr != nil {
			return nil, readErr
		}

		lock, parseErr := u.composerLockParser.Parse(rawComposerLock)
		if parseErr != nil {
			return nil, parseErr
		}

		findings = append(findings, u.composerLockParser.BuildAuditFindings(lock)...)
	}

	result := &domain.AuditScanResult{
		ProjectPath: projectPath,
		Ecosystem:   domain.EcosystemPHPComposer,
		Summary:     buildAuditSummary(findings),
		Findings:    findings,
	}

	return result, nil
}

func buildAuditSummary(findings []domain.AuditFinding) domain.AuditSummary {
	summary := domain.AuditSummary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
}
