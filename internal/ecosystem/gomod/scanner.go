// Package gomod implements ecosystem.Scanner for Go modules
// (go.mod + go.sum).
package gomod

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

// Ecosystem is the stable identifier for Go modules used in JSON output.
const Ecosystem = "go-mod"
const osvEcosystem = "Go"

type Scanner struct {
	reader              *filesystem.Reader
	goMod               *parser.GoModParser
	goSum               *parser.GoSumParser
	vulnerabilitySource ecosystem.VulnerabilitySource
}

func NewScanner(reader *filesystem.Reader, vulnerabilitySource ecosystem.VulnerabilitySource) *Scanner {
	return &Scanner{
		reader:              reader,
		goMod:               parser.NewGoModParser(),
		goSum:               parser.NewGoSumParser(),
		vulnerabilitySource: vulnerabilitySource,
	}
}

func (s *Scanner) Name() string { return Ecosystem }

func (s *Scanner) Detect(path string) (bool, map[string]bool, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return false, nil, err
	}

	hasGoMod, err := s.reader.FileExists(filepath.Join(resolved, "go.mod"))
	if err != nil {
		return false, nil, err
	}
	if !hasGoMod {
		return false, nil, nil
	}

	hasGoSum, err := s.reader.FileExists(filepath.Join(resolved, "go.sum"))
	if err != nil {
		return false, nil, err
	}

	return true, map[string]bool{
		"go.mod": hasGoMod,
		"go.sum": hasGoSum,
	}, nil
}

func (s *Scanner) ListDirectDependencies(path string, includeDev bool) ([]domain.DirectDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	raw, err := s.reader.ReadFile(filepath.Join(resolved, "go.mod"))
	if err != nil {
		return nil, err
	}

	manifest, err := s.goMod.Parse(raw)
	if err != nil {
		return nil, err
	}

	return s.goMod.BuildDirectDependencies(manifest, includeDev), nil
}

func (s *Scanner) ListLockedDependencies(path string) ([]domain.LockedDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	goSumPath := filepath.Join(resolved, "go.sum")
	exists, err := s.reader.FileExists(goSumPath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.NewAppError(domain.CodeLockfileNotFound, "go.sum file was not found", nil)
	}

	raw, err := s.reader.ReadFile(goSumPath)
	if err != nil {
		return nil, err
	}

	lock, err := s.goSum.Parse(raw)
	if err != nil {
		return nil, err
	}

	return s.goSum.BuildLockedDependencies(lock), nil
}

func (s *Scanner) BuildAuditFindings(path string) ([]domain.AuditFinding, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	rawMod, err := s.reader.ReadFile(filepath.Join(resolved, "go.mod"))
	if err != nil {
		return nil, err
	}

	manifest, err := s.goMod.Parse(rawMod)
	if err != nil {
		return nil, err
	}

	hasGoSum, err := s.reader.FileExists(filepath.Join(resolved, "go.sum"))
	if err != nil {
		return nil, err
	}

	findings := s.goMod.BuildAuditFindings(manifest, hasGoSum)

	if hasGoSum {
		rawSum, err := s.reader.ReadFile(filepath.Join(resolved, "go.sum"))
		if err != nil {
			return nil, err
		}

		lock, err := s.goSum.Parse(rawSum)
		if err != nil {
			return nil, err
		}
		lockedDeps := s.goSum.BuildLockedDependencies(lock)
		findings = append(findings, s.goSum.BuildAuditFindings(lock)...)

		if s.vulnerabilitySource != nil {
			remoteFindings, err := s.vulnerabilitySource.BuildAuditFindings(context.Background(), osvEcosystem, lockedDeps)
			if err != nil {
				findings = append(findings, domain.AuditFinding{
					ID:         "VULNERABILITY_SOURCE_UNAVAILABLE",
					Title:      "Remote vulnerability lookup unavailable",
					Severity:   "info",
					Category:   "scanner",
					Message:    "OSV vulnerability lookup for go.sum failed; results include only local audit heuristics: " + err.Error(),
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
