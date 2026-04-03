package python

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/ecosystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
	"github.com/hugooluisss/dependency_auditory_cli/internal/parser"
)

const Ecosystem = "python"
const osvEcosystem = "PyPI"

type Scanner struct {
	reader              *filesystem.Reader
	requirements        *parser.RequirementsParser
	pythonLockParser    *parser.PythonLockParser
	vulnerabilitySource ecosystem.VulnerabilitySource
}

func NewScanner(reader *filesystem.Reader, vulnerabilitySource ecosystem.VulnerabilitySource) *Scanner {
	return &Scanner{
		reader:              reader,
		requirements:        parser.NewRequirementsParser(),
		pythonLockParser:    parser.NewPythonLockParser(),
		vulnerabilitySource: vulnerabilitySource,
	}
}

func (s *Scanner) Name() string { return Ecosystem }

func (s *Scanner) Detect(path string) (bool, map[string]bool, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return false, nil, err
	}

	manifests := map[string]bool{}
	tracked := []string{
		"requirements.txt",
		"requirements-dev.txt",
		"pyproject.toml",
		"Pipfile",
		"poetry.lock",
		"Pipfile.lock",
		"requirements.lock",
	}

	foundManifest := false
	for _, file := range tracked {
		exists, err := s.reader.FileExists(filepath.Join(resolved, file))
		if err != nil {
			return false, nil, err
		}
		manifests[file] = exists
		if file == "requirements.txt" || file == "pyproject.toml" || file == "Pipfile" {
			foundManifest = foundManifest || exists
		}
	}

	if !foundManifest {
		return false, nil, nil
	}

	return true, manifests, nil
}

func (s *Scanner) ListDirectDependencies(path string, includeDev bool) ([]domain.DirectDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	main, err := s.readRequirements(filepath.Join(resolved, "requirements.txt"))
	if err != nil {
		return nil, err
	}

	dev := make([]parser.RequirementEntry, 0)
	if includeDev {
		dev, err = s.readRequirements(filepath.Join(resolved, "requirements-dev.txt"))
		if err != nil {
			return nil, err
		}
	}

	return s.requirements.BuildDirectDependencies(main, dev, includeDev), nil
}

func (s *Scanner) ListLockedDependencies(path string) ([]domain.LockedDependency, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	lockType, lockPath, exists, err := s.resolveLock(resolved)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.NewAppError(domain.CodeLockfileNotFound, "poetry.lock, Pipfile.lock, or requirements.lock file was not found", nil)
	}

	raw, err := s.reader.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	switch lockType {
	case "poetry":
		parsed, err := s.pythonLockParser.ParsePoetryLock(raw)
		if err != nil {
			return nil, err
		}
		return s.pythonLockParser.BuildLockedFromPoetryLock(parsed), nil
	case "pipfile":
		parsed, err := s.pythonLockParser.ParsePipfileLock(raw)
		if err != nil {
			return nil, err
		}
		return s.pythonLockParser.BuildLockedFromPipfileLock(parsed), nil
	default:
		parsed, err := s.requirements.Parse(raw)
		if err != nil {
			return nil, err
		}
		return s.pythonLockParser.BuildLockedFromRequirementsLock(parsed), nil
	}
}

func (s *Scanner) BuildAuditFindings(path string) ([]domain.AuditFinding, error) {
	resolved, err := s.reader.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	main, err := s.readRequirements(filepath.Join(resolved, "requirements.txt"))
	if err != nil {
		return nil, err
	}
	dev, err := s.readRequirements(filepath.Join(resolved, "requirements-dev.txt"))
	if err != nil {
		return nil, err
	}

	_, lockPath, hasLock, err := s.resolveLock(resolved)
	if err != nil {
		return nil, err
	}

	findings := s.requirements.BuildAuditFindings(main, dev, hasLock)

	if hasLock {
		deps, err := s.ListLockedDependencies(path)
		if err != nil {
			return nil, err
		}
		findings = append(findings, s.pythonLockParser.BuildAuditFindings(deps)...)

		if s.vulnerabilitySource != nil {
			remoteFindings, err := s.vulnerabilitySource.BuildAuditFindings(context.Background(), osvEcosystem, deps)
			if err != nil {
				findings = append(findings, domain.AuditFinding{
					ID:         "VULNERABILITY_SOURCE_UNAVAILABLE",
					Title:      "Remote vulnerability lookup unavailable",
					Severity:   "info",
					Category:   "scanner",
					Message:    "OSV vulnerability lookup for Python lockfile failed; results include only local audit heuristics: " + err.Error(),
					Confidence: "high",
				})
			} else {
				findings = append(findings, remoteFindings...)
			}
		}

		if lockPath == filepath.Join(resolved, "requirements.lock") {
			findings = append(findings, lockCompletenessFindings(deps)...)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		leftRank := auditSeverityRank(findings[i].Severity)
		rightRank := auditSeverityRank(findings[j].Severity)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Scope != findings[j].Scope {
			return findings[i].Scope < findings[j].Scope
		}
		return findings[i].Package < findings[j].Package
	})

	return findings, nil
}

func (s *Scanner) resolveLock(resolvedPath string) (string, string, bool, error) {
	order := []struct {
		Type string
		File string
	}{
		{Type: "poetry", File: "poetry.lock"},
		{Type: "pipfile", File: "Pipfile.lock"},
		{Type: "requirements", File: "requirements.lock"},
	}

	for _, candidate := range order {
		fullPath := filepath.Join(resolvedPath, candidate.File)
		exists, err := s.reader.FileExists(fullPath)
		if err != nil {
			return "", "", false, err
		}
		if exists {
			return candidate.Type, fullPath, true, nil
		}
	}

	return "", "", false, nil
}

func (s *Scanner) readRequirements(path string) ([]parser.RequirementEntry, error) {
	exists, err := s.reader.FileExists(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return []parser.RequirementEntry{}, nil
	}

	raw, err := s.reader.ReadFile(path)
	if err != nil {
		return nil, err
	}

	entries, err := s.requirements.Parse(raw)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func lockCompletenessFindings(deps []domain.LockedDependency) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	for _, dep := range deps {
		if dep.Version == "" {
			findings = append(findings, domain.AuditFinding{
				ID:         "UNPINNED_LOCK_ENTRY",
				Title:      "requirements.lock entry is not pinned",
				Severity:   "medium",
				Category:   "supply-chain",
				Package:    dep.Name,
				Scope:      dep.Scope,
				Message:    "requirements.lock should use fully pinned versions (==).",
				Confidence: "high",
			})
		}
	}
	return findings
}

func auditSeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}
