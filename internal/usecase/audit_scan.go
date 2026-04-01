package usecase

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
)

type AuditScanUseCase struct {
	registry *ecosystem.Registry
}

func NewAuditScanUseCase(registry *ecosystem.Registry) *AuditScanUseCase {
	return &AuditScanUseCase{registry: registry}
}

func (u *AuditScanUseCase) Execute(projectPath string) (*domain.AuditScanResult, error) {
	scanner, _, err := u.registry.Detect(projectPath)
	if err != nil {
		return nil, err
	}

	findings, err := scanner.BuildAuditFindings(projectPath)
	if err != nil {
		return nil, err
	}

	return &domain.AuditScanResult{
		ProjectPath: projectPath,
		Ecosystem:   scanner.Name(),
		Summary:     buildAuditSummary(findings),
		Findings:    findings,
	}, nil
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
