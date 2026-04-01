package parser

import (
	"bufio"
	"encoding/json"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
	Index   string `json:"index"`
}

type poetryPackage struct {
	Name    string
	Version string
}

type PythonLockParser struct{}

func NewPythonLockParser() *PythonLockParser {
	return &PythonLockParser{}
}

func (p *PythonLockParser) ParsePipfileLock(raw []byte) (*pipfileLock, error) {
	var parsed pipfileLock
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, domain.NewAppError(domain.CodeInvalidJSON, "Pipfile.lock contains invalid JSON", err)
	}
	if parsed.Default == nil {
		parsed.Default = map[string]pipfilePackage{}
	}
	if parsed.Develop == nil {
		parsed.Develop = map[string]pipfilePackage{}
	}
	return &parsed, nil
}

func (p *PythonLockParser) ParsePoetryLock(raw []byte) ([]poetryPackage, error) {
	packages := make([]poetryPackage, 0)
	current := poetryPackage{}
	inPackage := false

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if inPackage && current.Name != "" {
				packages = append(packages, current)
			}
			current = poetryPackage{}
			inPackage = true
			continue
		}
		if !inPackage || line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			current.Name = trimQuoted(strings.TrimPrefix(line, "name = "))
			continue
		}
		if strings.HasPrefix(line, "version = ") {
			current.Version = trimQuoted(strings.TrimPrefix(line, "version = "))
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, domain.NewAppError(domain.CodeReadError, "Could not parse poetry.lock", err)
	}

	if inPackage && current.Name != "" {
		packages = append(packages, current)
	}

	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		return packages[i].Version < packages[j].Version
	})

	return packages, nil
}

func (p *PythonLockParser) BuildLockedFromPipfileLock(parsed *pipfileLock) []domain.LockedDependency {
	deps := make([]domain.LockedDependency, 0, len(parsed.Default)+len(parsed.Develop))

	for _, name := range sortedPipfileKeys(parsed.Default) {
		pkg := parsed.Default[name]
		deps = append(deps, domain.LockedDependency{
			Name:            name,
			Version:         strings.TrimPrefix(pkg.Version, "=="),
			Scope:           "default",
			SourceReference: pkg.Index,
		})
	}
	for _, name := range sortedPipfileKeys(parsed.Develop) {
		pkg := parsed.Develop[name]
		deps = append(deps, domain.LockedDependency{
			Name:            name,
			Version:         strings.TrimPrefix(pkg.Version, "=="),
			Scope:           "develop",
			SourceReference: pkg.Index,
		})
	}

	return deps
}

func (p *PythonLockParser) BuildLockedFromPoetryLock(packages []poetryPackage) []domain.LockedDependency {
	deps := make([]domain.LockedDependency, 0, len(packages))
	for _, pkg := range packages {
		deps = append(deps, domain.LockedDependency{
			Name:    pkg.Name,
			Version: pkg.Version,
			Scope:   "package",
		})
	}
	return deps
}

func (p *PythonLockParser) BuildLockedFromRequirementsLock(entries []RequirementEntry) []domain.LockedDependency {
	deps := make([]domain.LockedDependency, 0, len(entries))
	for _, entry := range entries {
		version := strings.TrimSpace(entry.Constraint)
		version = strings.TrimPrefix(version, "==")
		deps = append(deps, domain.LockedDependency{
			Name:    entry.Name,
			Version: version,
			Scope:   "requirements-lock",
		})
	}

	sort.SliceStable(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})

	return deps
}

func (p *PythonLockParser) BuildAuditFindings(deps []domain.LockedDependency) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	for _, dep := range deps {
		if strings.TrimSpace(dep.Version) == "" {
			findings = append(findings, domain.AuditFinding{
				ID:         "UNPINNED_LOCK_ENTRY",
				Title:      "Lock entry does not include a pinned version",
				Severity:   "low",
				Category:   "metadata",
				Package:    dep.Name,
				Scope:      dep.Scope,
				Message:    "Dependency in lock source has an empty version.",
				Confidence: "medium",
			})
		}
	}
	sortAuditFindings(findings)
	return findings
}

func sortedPipfileKeys(values map[string]pipfilePackage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func trimQuoted(value string) string {
	return strings.Trim(strings.TrimSpace(value), "\"")
}
