package usecase

import (
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

type ListDirectDependenciesUseCase struct {
	reader *filesystem.Reader
	parser *parser.ComposerJSONParser
}

func NewListDirectDependenciesUseCase(reader *filesystem.Reader, parser *parser.ComposerJSONParser) *ListDirectDependenciesUseCase {
	return &ListDirectDependenciesUseCase{reader: reader, parser: parser}
}

func (u *ListDirectDependenciesUseCase) Execute(projectPath string, includeDev bool) (*domain.DirectDependenciesResult, error) {
	resolvedPath, err := u.reader.ResolvePath(projectPath)
	if err != nil {
		return nil, err
	}

	composerJSONPath := filepath.Join(resolvedPath, "composer.json")
	exists, err := u.reader.FileExists(composerJSONPath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.NewAppError(
			domain.CodeProjectNotSupported,
			"No composer.json file was found in the target path",
			nil,
		)
	}

	raw, err := u.reader.ReadFile(composerJSONPath)
	if err != nil {
		return nil, err
	}

	manifest, err := u.parser.Parse(raw)
	if err != nil {
		return nil, err
	}

	deps := u.parser.BuildDirectDependencies(manifest, includeDev)
	return &domain.DirectDependenciesResult{
		ProjectPath:  projectPath,
		Ecosystem:    domain.EcosystemPHPComposer,
		Dependencies: deps,
	}, nil
}
