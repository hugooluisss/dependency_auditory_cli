package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type packageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

type PackageJSONParser struct{}

func NewPackageJSONParser() *PackageJSONParser {
	return &PackageJSONParser{}
}

func (p *PackageJSONParser) Parse(raw []byte) (*packageJSON, error) {
	var parsed packageJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, domain.NewAppError(domain.CodeInvalidJSON, "package.json contains invalid JSON", err)
	}

	if parsed.Dependencies == nil {
		parsed.Dependencies = map[string]string{}
	}
	if parsed.DevDependencies == nil {
		parsed.DevDependencies = map[string]string{}
	}
	if parsed.Scripts == nil {
		parsed.Scripts = map[string]string{}
	}

	return &parsed, nil
}

func (p *PackageJSONParser) BuildDirectDependencies(parsed *packageJSON, includeDev bool) []domain.DirectDependency {
	deps := make([]domain.DirectDependency, 0, len(parsed.Dependencies)+len(parsed.DevDependencies))

	for _, name := range sortedMapKeys(parsed.Dependencies) {
		deps = append(deps, domain.DirectDependency{
			Name:              name,
			VersionConstraint: parsed.Dependencies[name],
			Scope:             "dependencies",
		})
	}

	if includeDev {
		for _, name := range sortedMapKeys(parsed.DevDependencies) {
			deps = append(deps, domain.DirectDependency{
				Name:              name,
				VersionConstraint: parsed.DevDependencies[name],
				Scope:             "devDependencies",
			})
		}
	}

	return deps
}

func (p *PackageJSONParser) BuildAuditFindings(parsed *packageJSON, hasLockfile bool) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)

	if !hasLockfile {
		findings = append(findings, domain.AuditFinding{
			ID:         "MISSING_LOCKFILE",
			Title:      "package-lock.json is missing",
			Severity:   "medium",
			Category:   "supply-chain",
			Message:    "The project does not include package-lock.json or npm-shrinkwrap.json, which reduces dependency reproducibility.",
			Confidence: "high",
		})
	}

	findings = append(findings, scanNPMConstraints(parsed.Dependencies, "dependencies")...)
	findings = append(findings, scanNPMConstraints(parsed.DevDependencies, "devDependencies")...)
	findings = append(findings, scanNPMScripts(parsed.Scripts)...)

	sortAuditFindings(findings)
	return findings
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func scanNPMConstraints(values map[string]string, scope string) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	for _, name := range sortedMapKeys(values) {
		constraint := strings.TrimSpace(values[name])
		lower := strings.ToLower(constraint)

		if isNPMUnsafeConstraint(lower) {
			findings = append(findings, domain.AuditFinding{
				ID:         "UNSAFE_VERSION_CONSTRAINT",
				Title:      "Dependency uses an unsafe or unpinned version constraint",
				Severity:   "medium",
				Category:   "supply-chain",
				Package:    name,
				Scope:      scope,
				Message:    fmt.Sprintf("Constraint %q may pull unexpected versions.", constraint),
				Confidence: "medium",
			})
		}

		if isNPMDevelopmentConstraint(lower) {
			findings = append(findings, domain.AuditFinding{
				ID:         "DEV_BRANCH_CONSTRAINT",
				Title:      "Dependency tracks a development branch",
				Severity:   "high",
				Category:   "supply-chain",
				Package:    name,
				Scope:      scope,
				Message:    fmt.Sprintf("Constraint %q references development builds or non-registry sources.", constraint),
				Confidence: "high",
			})
		}
	}
	return findings
}

func isNPMUnsafeConstraint(lower string) bool {
	return lower == "*" || lower == "latest" || lower == "x" || strings.HasSuffix(lower, ".x")
}

func isNPMDevelopmentConstraint(lower string) bool {
	return strings.HasPrefix(lower, "github:") ||
		strings.HasPrefix(lower, "git+") ||
		strings.HasPrefix(lower, "git://") ||
		strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "file:") ||
		strings.Contains(lower, "#")
}

func scanNPMScripts(scripts map[string]string) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	for _, hook := range sortedMapKeys(scripts) {
		command := scripts[hook]
		if containsNPMRiskyCommand(command) {
			findings = append(findings, domain.AuditFinding{
				ID:         "RISKY_SCRIPT_COMMAND",
				Title:      "npm script contains risky command patterns",
				Severity:   "high",
				Category:   "script-execution",
				Scope:      hook,
				Message:    fmt.Sprintf("Script %q contains command %q.", hook, command),
				Confidence: "medium",
			})
		}
	}
	return findings
}

func containsNPMRiskyCommand(command string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(curl|wget).*(\||bash|sh)`),
		regexp.MustCompile(`(?i)powershell`),
		regexp.MustCompile(`(?i)base64\s+-d`),
		regexp.MustCompile(`(?i)eval\s+`),
		regexp.MustCompile(`(?i)chmod\s+777`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(command) {
			return true
		}
	}

	return false
}
