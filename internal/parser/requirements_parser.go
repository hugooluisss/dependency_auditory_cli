package parser

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type RequirementEntry struct {
	Name       string
	Constraint string
}

type RequirementsParser struct{}

func NewRequirementsParser() *RequirementsParser {
	return &RequirementsParser{}
}

func (p *RequirementsParser) Parse(raw []byte) ([]RequirementEntry, error) {
	entries := make([]RequirementEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))

	for scanner.Scan() {
		line := cleanRequirementLine(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}

		name, constraint, ok := splitRequirement(line)
		if !ok {
			continue
		}
		entries = append(entries, RequirementEntry{Name: name, Constraint: constraint})
	}

	if err := scanner.Err(); err != nil {
		return nil, domain.NewAppError(domain.CodeReadError, "Could not parse requirements file", err)
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Constraint < entries[j].Constraint
	})

	return entries, nil
}

func (p *RequirementsParser) BuildDirectDependencies(main, dev []RequirementEntry, includeDev bool) []domain.DirectDependency {
	deps := make([]domain.DirectDependency, 0, len(main)+len(dev))

	for _, entry := range main {
		deps = append(deps, domain.DirectDependency{
			Name:              entry.Name,
			VersionConstraint: entry.Constraint,
			Scope:             "requirements",
		})
	}

	if includeDev {
		for _, entry := range dev {
			deps = append(deps, domain.DirectDependency{
				Name:              entry.Name,
				VersionConstraint: entry.Constraint,
				Scope:             "requirements-dev",
			})
		}
	}

	return deps
}

func (p *RequirementsParser) BuildAuditFindings(main, dev []RequirementEntry, hasLockfile bool) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)

	if !hasLockfile {
		findings = append(findings, domain.AuditFinding{
			ID:         "MISSING_LOCKFILE",
			Title:      "Python lockfile is missing",
			Severity:   "medium",
			Category:   "supply-chain",
			Message:    "The project does not include poetry.lock, Pipfile.lock, or requirements.lock.",
			Confidence: "high",
		})
	}

	for _, entry := range main {
		findings = append(findings, requirementFindings(entry, "requirements")...)
	}
	for _, entry := range dev {
		findings = append(findings, requirementFindings(entry, "requirements-dev")...)
	}

	sortAuditFindings(findings)
	return findings
}

func requirementFindings(entry RequirementEntry, scope string) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	lower := strings.ToLower(strings.TrimSpace(entry.Constraint))

	if lower == "" {
		findings = append(findings, domain.AuditFinding{
			ID:         "UNPINNED_DEPENDENCY",
			Title:      "Dependency has no version constraint",
			Severity:   "low",
			Category:   "supply-chain",
			Package:    entry.Name,
			Scope:      scope,
			Message:    "Requirement does not define any version constraint.",
			Confidence: "high",
		})
	}

	if strings.Contains(lower, "*") || lower == "latest" {
		findings = append(findings, domain.AuditFinding{
			ID:         "UNSAFE_VERSION_CONSTRAINT",
			Title:      "Dependency uses an unsafe version constraint",
			Severity:   "medium",
			Category:   "supply-chain",
			Package:    entry.Name,
			Scope:      scope,
			Message:    fmt.Sprintf("Constraint %q may pull unexpected versions.", entry.Constraint),
			Confidence: "medium",
		})
	}

	if strings.Contains(lower, "git+") || strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, "@") {
		findings = append(findings, domain.AuditFinding{
			ID:         "REMOTE_SOURCE_CONSTRAINT",
			Title:      "Dependency references remote source",
			Severity:   "high",
			Category:   "supply-chain",
			Package:    entry.Name,
			Scope:      scope,
			Message:    fmt.Sprintf("Constraint %q references non-registry source or direct URL.", entry.Constraint),
			Confidence: "high",
		})
	}

	return findings
}

func cleanRequirementLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}

	if idx := strings.Index(trimmed, " #"); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	if idx := strings.Index(trimmed, ";"); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}

	return trimmed
}

func splitRequirement(line string) (string, string, bool) {
	operators := []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"}
	for _, op := range operators {
		if idx := strings.Index(line, op); idx > 0 {
			name := normalizeRequirementName(line[:idx])
			constraint := strings.TrimSpace(line[idx:])
			if name == "" {
				return "", "", false
			}
			return name, constraint, true
		}
	}

	name := normalizeRequirementName(line)
	if name == "" {
		return "", "", false
	}
	return name, "", true
}

func normalizeRequirementName(value string) string {
	name := strings.TrimSpace(value)
	if idx := strings.Index(name, "["); idx >= 0 {
		name = name[:idx]
	}
	name = strings.TrimSpace(name)
	if strings.Contains(name, " ") {
		return ""
	}
	return name
}
