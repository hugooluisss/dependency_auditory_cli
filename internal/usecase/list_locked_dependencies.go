package usecase

import (
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

type ListLockedDependenciesUseCase struct {
	reader *filesystem.Reader
	parser *parser.ComposerLockParser
}

func NewListLockedDependenciesUseCase(reader *filesystem.Reader, parser *parser.ComposerLockParser) *ListLockedDependenciesUseCase {
	return &ListLockedDependenciesUseCase{reader: reader, parser: parser}
}

func (u *ListLockedDependenciesUseCase) Execute(projectPath string) (*domain.LockedDependenciesResult, error) {
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

	hasLockfile, err := u.reader.FileExists(composerLockPath)
	if err != nil {
		return nil, err
	}
	if !hasLockfile {
		return nil, domain.NewAppError(
			domain.CodeLockfileNotFound,
			"composer.lock file was not found",
			nil,
		)
	}

	raw, err := u.reader.ReadFile(composerLockPath)
	if err != nil {
		return nil, err
	}

	lock, err := u.parser.Parse(raw)
	if err != nil {
		return nil, err
	}

	deps := u.parser.BuildLockedDependencies(lock)
	return &domain.LockedDependenciesResult{
		ProjectPath:  projectPath,
		Ecosystem:    domain.EcosystemPHPComposer,
		Dependencies: deps,
	}, nil
}
