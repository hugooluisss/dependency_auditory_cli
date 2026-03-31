package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type composerJSON struct {
	Name             string                     `json:"name"`
	Require          map[string]string          `json:"require"`
	RequireDev       map[string]string          `json:"require-dev"`
	Scripts          map[string]json.RawMessage `json:"scripts"`
	MinimumStability string                     `json:"minimum-stability"`
	PreferStable     bool                       `json:"prefer-stable"`
}

type ComposerJSONParser struct{}

func NewComposerJSONParser() *ComposerJSONParser {
	return &ComposerJSONParser{}
}

func (p *ComposerJSONParser) Parse(raw []byte) (*composerJSON, error) {
	var parsed composerJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, domain.NewAppError(domain.CodeInvalidJSON, "composer.json contains invalid JSON", err)
	}

	if parsed.Require == nil {
		parsed.Require = map[string]string{}
	}
	if parsed.RequireDev == nil {
		parsed.RequireDev = map[string]string{}
	}

	return &parsed, nil
}

func (p *ComposerJSONParser) BuildDirectDependencies(parsed *composerJSON, includeDev bool) []domain.DirectDependency {
	deps := make([]domain.DirectDependency, 0, len(parsed.Require)+len(parsed.RequireDev))

	requireNames := mapKeysSorted(parsed.Require)
	for _, name := range requireNames {
		deps = append(deps, domain.DirectDependency{
			Name:              name,
			VersionConstraint: parsed.Require[name],
			Scope:             "require",
		})
	}

	if includeDev {
		requireDevNames := mapKeysSorted(parsed.RequireDev)
		for _, name := range requireDevNames {
			deps = append(deps, domain.DirectDependency{
				Name:              name,
				VersionConstraint: parsed.RequireDev[name],
				Scope:             "require-dev",
			})
		}
	}

	return deps
}

func mapKeysSorted(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (p *ComposerJSONParser) BuildAuditFindings(parsed *composerJSON, hasLockfile bool) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)

	if !hasLockfile {
		findings = append(findings, domain.AuditFinding{
			ID:         "MISSING_LOCKFILE",
			Title:      "composer.lock is missing",
			Severity:   "medium",
			Category:   "supply-chain",
			Message:    "The project does not include composer.lock, which reduces dependency reproducibility.",
			Confidence: "high",
		})
	}

	if isUnstable(parsed.MinimumStability) {
		findings = append(findings, domain.AuditFinding{
			ID:         "UNSTABLE_MINIMUM_STABILITY",
			Title:      "minimum-stability allows unstable packages",
			Severity:   "medium",
			Category:   "policy",
			Message:    fmt.Sprintf("minimum-stability is set to %q.", parsed.MinimumStability),
			Confidence: "high",
		})
	}

	findings = append(findings, scanConstraints(parsed.Require, "require")...)
	findings = append(findings, scanConstraints(parsed.RequireDev, "require-dev")...)
	findings = append(findings, scanScripts(parsed.Scripts)...)

	sortAuditFindings(findings)
	return findings
}

func scanConstraints(values map[string]string, scope string) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	for _, name := range mapKeysSorted(values) {
		constraint := strings.TrimSpace(values[name])
		if isUnsafeConstraint(constraint) {
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

		if strings.Contains(strings.ToLower(constraint), "@dev") || strings.HasPrefix(strings.ToLower(constraint), "dev-") {
			findings = append(findings, domain.AuditFinding{
				ID:         "DEV_BRANCH_CONSTRAINT",
				Title:      "Dependency tracks a development branch",
				Severity:   "high",
				Category:   "supply-chain",
				Package:    name,
				Scope:      scope,
				Message:    fmt.Sprintf("Constraint %q references development builds.", constraint),
				Confidence: "high",
			})
		}
	}
	return findings
}

func scanScripts(scripts map[string]json.RawMessage) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	for hook := range scripts {
		commands := normalizeCommands(scripts[hook])
		for _, command := range commands {
			if containsRiskyCommand(command) {
				findings = append(findings, domain.AuditFinding{
					ID:         "RISKY_SCRIPT_COMMAND",
					Title:      "Composer script contains risky command patterns",
					Severity:   "high",
					Category:   "script-execution",
					Scope:      hook,
					Message:    fmt.Sprintf("Script %q contains command %q.", hook, command),
					Confidence: "medium",
				})
			}
		}
	}
	return findings
}

func normalizeCommands(raw json.RawMessage) []string {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if strings.TrimSpace(single) != "" {
			return []string{single}
		}
		return nil
	}

	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		commands := make([]string, 0, len(list))
		for _, command := range list {
			if strings.TrimSpace(command) != "" {
				commands = append(commands, command)
			}
		}
		return commands
	}

	return nil
}

func containsRiskyCommand(command string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(curl|wget).*(\||bash|sh)`),
		regexp.MustCompile(`(?i)powershell`),
		regexp.MustCompile(`(?i)base64_decode\(`),
		regexp.MustCompile(`(?i)eval\(`),
		regexp.MustCompile(`(?i)chmod\s+777`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

func isUnsafeConstraint(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "*" || lower == "dev-master" || strings.Contains(lower, "@dev")
}

func isUnstable(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "dev" || lower == "alpha" || lower == "beta" || lower == "rc"
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
		return findings[i].Package < findings[j].Package
	})
}
