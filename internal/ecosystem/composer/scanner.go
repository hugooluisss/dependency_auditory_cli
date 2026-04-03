// Package composer implements ecosystem.Scanner for PHP Composer projects
// (composer.json + composer.lock).
package composer

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

// Ecosystem is the stable identifier for PHP Composer used in JSON output.
const Ecosystem = "php-composer"
const osvEcosystem = "Packagist"

// Scanner implements ecosystem.Scanner for PHP Composer.
type Scanner struct {
	reader              *filesystem.Reader
	jsonParser          *parser.ComposerJSONParser
	lockParser          *parser.ComposerLockParser
	vulnerabilitySource ecosystem.VulnerabilitySource
}

// NewScanner returns a Composer Scanner backed by the given filesystem reader.
func NewScanner(reader *filesystem.Reader, vulnerabilitySource ecosystem.VulnerabilitySource) *Scanner {
	return &Scanner{
		reader:              reader,
		jsonParser:          parser.NewComposerJSONParser(),
		lockParser:          parser.NewComposerLockParser(),
		vulnerabilitySource: vulnerabilitySource,
	}
}

func (s *Scanner) Name() string { return Ecosystem }

// Detect reports whether composer.json is present at path and returns the
// presence status of both Composer manifest files.
func (s *Scanner) Detect(path string) (bool, map[string]bool, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return false, nil, err
	}

	hasJSON, err := s.reader.FileExists(filepath.Join(resolved, "composer.json"))
	if err != nil {
		return false, nil, err
	}
	if !hasJSON {
		return false, nil, nil
	}

	hasLock, err := s.reader.FileExists(filepath.Join(resolved, "composer.lock"))
	if err != nil {
		return false, nil, err
	}

	return true, map[string]bool{
		"composer.json": true,
		"composer.lock": hasLock,
	}, nil
}

// ListDirectDependencies parses composer.json and returns declared dependencies.
func (s *Scanner) ListDirectDependencies(path string, includeDev bool) ([]domain.DirectDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	raw, err := s.reader.ReadFile(filepath.Join(resolved, "composer.json"))
	if err != nil {
		return nil, err
	}

	manifest, err := s.jsonParser.Parse(raw)
	if err != nil {
		return nil, err
	}

	return s.jsonParser.BuildDirectDependencies(manifest, includeDev), nil
}

// ListLockedDependencies parses composer.lock and returns pinned packages.
// Returns LOCKFILE_NOT_FOUND when composer.lock is absent.
func (s *Scanner) ListLockedDependencies(path string) ([]domain.LockedDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	lockPath := filepath.Join(resolved, "composer.lock")
	exists, err := s.reader.FileExists(lockPath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.NewAppError(domain.CodeLockfileNotFound, "composer.lock file was not found", nil)
	}

	raw, err := s.reader.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	lock, err := s.lockParser.Parse(raw)
	if err != nil {
		return nil, err
	}

	return s.lockParser.BuildLockedDependencies(lock), nil
}

// BuildAuditFindings runs offline heuristics on composer.json and composer.lock.
func (s *Scanner) BuildAuditFindings(path string) ([]domain.AuditFinding, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	raw, err := s.reader.ReadFile(filepath.Join(resolved, "composer.json"))
	if err != nil {
		return nil, err
	}

	manifest, err := s.jsonParser.Parse(raw)
	if err != nil {
		return nil, err
	}

	hasLock, err := s.reader.FileExists(filepath.Join(resolved, "composer.lock"))
	if err != nil {
		return nil, err
	}

	findings := s.jsonParser.BuildAuditFindings(manifest, hasLock)

	if hasLock {
		rawLock, err := s.reader.ReadFile(filepath.Join(resolved, "composer.lock"))
		if err != nil {
			return nil, err
		}
		lock, err := s.lockParser.Parse(rawLock)
		if err != nil {
			return nil, err
		}

		lockedDeps := s.lockParser.BuildLockedDependencies(lock)
		findings = append(findings, s.lockParser.BuildAuditFindings(lock)...)

		if s.vulnerabilitySource != nil {
			remoteFindings, err := s.vulnerabilitySource.BuildAuditFindings(context.Background(), osvEcosystem, lockedDeps)
			if err != nil {
				findings = append(findings, domain.AuditFinding{
					ID:         "VULNERABILITY_SOURCE_UNAVAILABLE",
					Title:      "Remote vulnerability lookup unavailable",
					Severity:   "info",
					Category:   "scanner",
					Message:    "OSV vulnerability lookup for composer.lock failed; results include only local audit heuristics: " + err.Error(),
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
