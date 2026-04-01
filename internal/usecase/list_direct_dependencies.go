package usecase

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
)

type ListDirectDependenciesUseCase struct {
	registry *ecosystem.Registry
}

func NewListDirectDependenciesUseCase(registry *ecosystem.Registry) *ListDirectDependenciesUseCase {
	return &ListDirectDependenciesUseCase{registry: registry}
}

func (u *ListDirectDependenciesUseCase) Execute(projectPath string, includeDev bool) (*domain.DirectDependenciesResult, error) {
	scanner, _, err := u.registry.Detect(projectPath)
	if err != nil {
		return nil, err
	}

	deps, err := scanner.ListDirectDependencies(projectPath, includeDev)
	if err != nil {
		return nil, err
	}

	return &domain.DirectDependenciesResult{
		ProjectPath:  projectPath,
		Ecosystem:    scanner.Name(),
		Dependencies: deps,
	}, nil
}
