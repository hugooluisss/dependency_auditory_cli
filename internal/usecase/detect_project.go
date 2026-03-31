package usecase

import (
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
)

type DetectProjectUseCase struct {
	reader *filesystem.Reader
}

func NewDetectProjectUseCase(reader *filesystem.Reader) *DetectProjectUseCase {
	return &DetectProjectUseCase{reader: reader}
}

func (u *DetectProjectUseCase) Execute(projectPath string) (*domain.ProjectDetectionResult, error) {
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

	hasComposerLock, err := u.reader.FileExists(composerLockPath)
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

	return &domain.ProjectDetectionResult{
		ProjectPath: projectPath,
		Ecosystem:   domain.EcosystemPHPComposer,
		Manifests: domain.Manifests{
			ComposerJSON: hasComposerJSON,
			ComposerLock: hasComposerLock,
		},
	}, nil
}
