// Package npm implements ecosystem.Scanner for npm projects
// (package.json + package-lock.json / npm-shrinkwrap.json).
package npm

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

// Ecosystem is the stable identifier for npm projects used in JSON output.
const Ecosystem = "npm"
const osvEcosystem = "npm"

type Scanner struct {
	reader              *filesystem.Reader
	packageJSON         *parser.PackageJSONParser
	packageLock         *parser.PackageLockParser
	vulnerabilitySource ecosystem.VulnerabilitySource
}

func NewScanner(reader *filesystem.Reader, vulnerabilitySource ecosystem.VulnerabilitySource) *Scanner {
	return &Scanner{
		reader:              reader,
		packageJSON:         parser.NewPackageJSONParser(),
		packageLock:         parser.NewPackageLockParser(),
		vulnerabilitySource: vulnerabilitySource,
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
		lockedDeps := s.packageLock.BuildLockedDependencies(lock)
		findings = append(findings, s.packageLock.BuildAuditFindings(lock)...)

		if s.vulnerabilitySource != nil {
			remoteFindings, err := s.vulnerabilitySource.BuildAuditFindings(context.Background(), osvEcosystem, lockedDeps)
			if err != nil {
				findings = append(findings, domain.AuditFinding{
					ID:         "VULNERABILITY_SOURCE_UNAVAILABLE",
					Title:      "Remote vulnerability lookup unavailable",
					Severity:   "info",
					Category:   "scanner",
					Message:    "OSV vulnerability lookup for npm lockfile failed; results include only local audit heuristics: " + err.Error(),
					Confidence: "high",
				})
			} else {
				findings = append(findings, remoteFindings...)
			}
		}
	}

	sortAuditFindings(findings)
	return findings, nil
}

func sortAuditFindings(findings []domain.AuditFinding) {
	severityRank := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.SliceStable(findings, func(i, j int) bool {
		leftRank, ok := severityRank[findings[i].Severity]
		if !ok {
			leftRank = 99
		}
		rightRank, ok := severityRank[findings[j].Severity]
		if !ok {
			rightRank = 99
		}
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Package != findings[j].Package {
			return findings[i].Package < findings[j].Package
		}
		return findings[i].Scope < findings[j].Scope
	})
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
