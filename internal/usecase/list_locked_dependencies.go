package usecase

import (
	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
)

type ListLockedDependenciesUseCase struct {
	registry *ecosystem.Registry
}

func NewListLockedDependenciesUseCase(registry *ecosystem.Registry) *ListLockedDependenciesUseCase {
	return &ListLockedDependenciesUseCase{registry: registry}
}

func (u *ListLockedDependenciesUseCase) Execute(projectPath string) (*domain.LockedDependenciesResult, error) {
	scanner, _, err := u.registry.Detect(projectPath)
	if err != nil {
		return nil, err
	}

	deps, err := scanner.ListLockedDependencies(projectPath)
	if err != nil {
		return nil, err
	}

	return &domain.LockedDependenciesResult{
		ProjectPath:  projectPath,
		Ecosystem:    scanner.Name(),
		Dependencies: deps,
	}, nil
}
