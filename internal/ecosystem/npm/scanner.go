// Package npm implements ecosystem.Scanner for npm projects
// (package.json + package-lock.json / npm-shrinkwrap.json).
package npm

import (
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

// Ecosystem is the stable identifier for npm projects used in JSON output.
const Ecosystem = "npm"

type Scanner struct {
	reader      *filesystem.Reader
	packageJSON *parser.PackageJSONParser
	packageLock *parser.PackageLockParser
}

func NewScanner(reader *filesystem.Reader) *Scanner {
	return &Scanner{
		reader:      reader,
		packageJSON: parser.NewPackageJSONParser(),
		packageLock: parser.NewPackageLockParser(),
	}
}

func (s *Scanner) Name() string { return Ecosystem }

func (s *Scanner) Detect(path string) (bool, map[string]bool, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return false, nil, err
	}

	hasPackageJSON, err := s.reader.FileExists(filepath.Join(resolved, "package.json"))
	if err != nil {
		return false, nil, err
	}
	if !hasPackageJSON {
		return false, nil, nil
	}

	hasPackageLock, err := s.reader.FileExists(filepath.Join(resolved, "package-lock.json"))
	if err != nil {
		return false, nil, err
	}
	hasShrinkwrap, err := s.reader.FileExists(filepath.Join(resolved, "npm-shrinkwrap.json"))
	if err != nil {
		return false, nil, err
	}

	return true, map[string]bool{
		"package.json":        true,
		"package-lock.json":   hasPackageLock,
		"npm-shrinkwrap.json": hasShrinkwrap,
	}, nil
}

func (s *Scanner) ListDirectDependencies(path string, includeDev bool) ([]domain.DirectDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	raw, err := s.reader.ReadFile(filepath.Join(resolved, "package.json"))
	if err != nil {
		return nil, err
	}

	manifest, err := s.packageJSON.Parse(raw)
	if err != nil {
		return nil, err
	}

	return s.packageJSON.BuildDirectDependencies(manifest, includeDev), nil
}

func (s *Scanner) ListLockedDependencies(path string) ([]domain.LockedDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	lockPath, exists, err := s.resolveLockPath(resolved)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.NewAppError(domain.CodeLockfileNotFound, "package-lock.json or npm-shrinkwrap.json file was not found", nil)
	}

	raw, err := s.reader.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	lock, err := s.packageLock.Parse(raw)
	if err != nil {
		return nil, err
	}

	return s.packageLock.BuildLockedDependencies(lock), nil
}

func (s *Scanner) BuildAuditFindings(path string) ([]domain.AuditFinding, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	rawManifest, err := s.reader.ReadFile(filepath.Join(resolved, "package.json"))
	if err != nil {
		return nil, err
	}

	manifest, err := s.packageJSON.Parse(rawManifest)
	if err != nil {
		return nil, err
	}

	lockPath, hasLock, err := s.resolveLockPath(resolved)
	if err != nil {
		return nil, err
	}

	findings := s.packageJSON.BuildAuditFindings(manifest, hasLock)

	if hasLock {
		rawLock, err := s.reader.ReadFile(lockPath)
		if err != nil {
			return nil, err
		}
		lock, err := s.packageLock.Parse(rawLock)
		if err != nil {
			return nil, err
		}
		findings = append(findings, s.packageLock.BuildAuditFindings(lock)...)
	}

	return findings, nil
}

func (s *Scanner) resolveLockPath(resolvedPath string) (string, bool, error) {
	packageLockPath := filepath.Join(resolvedPath, "package-lock.json")
	hasPackageLock, err := s.reader.FileExists(packageLockPath)
	if err != nil {
		return "", false, err
	}
	if hasPackageLock {
		return packageLockPath, true, nil
	}

	shrinkwrapPath := filepath.Join(resolvedPath, "npm-shrinkwrap.json")
	hasShrinkwrap, err := s.reader.FileExists(shrinkwrapPath)
	if err != nil {
		return "", false, err
	}
	if hasShrinkwrap {
		return shrinkwrapPath, true, nil
	}

	return "", false, nil
}
