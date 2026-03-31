package filesystem

import (
	"os"
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type Reader struct{}

func NewReader() *Reader {
	return &Reader{}
}

func (r *Reader) ResolvePath(path string) (string, error) {
	if path == "" {
		path = "."
	}

	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", domain.NewAppError(domain.CodeReadError, "Could not resolve path", err)
	}

	return resolved, nil
}

func (r *Reader) FileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, domain.NewAppError(domain.CodeReadError, "Could not check file existence", err)
	}

	return !info.IsDir(), nil
}

func (r *Reader) ReadFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.NewAppError(domain.CodeFileNotFound, "File was not found", err)
		}
		return nil, domain.NewAppError(domain.CodeReadError, "Could not read file", err)
	}

	return content, nil
}
