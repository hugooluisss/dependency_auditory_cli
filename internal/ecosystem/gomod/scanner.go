// Package gomod implements ecosystem.Scanner for Go modules
// (go.mod + go.sum).
package gomod

import (
	"path/filepath"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

// Ecosystem is the stable identifier for Go modules used in JSON output.
const Ecosystem = "go-mod"

type Scanner struct {
	reader *filesystem.Reader
	goMod  *parser.GoModParser
	goSum  *parser.GoSumParser
}

func NewScanner(reader *filesystem.Reader) *Scanner {
	return &Scanner{
		reader: reader,
		goMod:  parser.NewGoModParser(),
		goSum:  parser.NewGoSumParser(),
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
		findings = append(findings, s.goSum.BuildAuditFindings(lock)...)
	}

	return findings, nil
}
