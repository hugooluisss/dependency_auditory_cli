package usecase

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
)

type DetectProjectUseCase struct {
	registry *ecosystem.Registry
}

func NewDetectProjectUseCase(registry *ecosystem.Registry) *DetectProjectUseCase {
	return &DetectProjectUseCase{registry: registry}
}

func (u *DetectProjectUseCase) Execute(projectPath string) (*domain.ProjectDetectionResult, error) {
	scanner, manifests, err := u.registry.Detect(projectPath)
	if err != nil {
		return nil, err
	}
	return &domain.ProjectDetectionResult{
		ProjectPath: projectPath,
		Ecosystem:   scanner.Name(),
		Manifests:   manifests,
	}, nil
}
