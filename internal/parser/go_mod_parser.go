package parser

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type goMod struct {
	ModulePath string
	Requires   []goModRequire
	Replaces   []goModReplace
}

type goModRequire struct {
	Module   string
	Version  string
	Indirect bool
}

type goModReplace struct {
	OldModule  string
	OldVersion string
	NewTarget  string
}

type GoModParser struct{}

func NewGoModParser() *GoModParser {
	return &GoModParser{}
}

func (p *GoModParser) Parse(raw []byte) (*goMod, error) {
	parsed := &goMod{
		Requires: make([]goModRequire, 0),
		Replaces: make([]goModReplace, 0),
	}

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	lineNo := 0
	inRequireBlock := false
	inReplaceBlock := false

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "module ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				parsed.ModulePath = parts[1]
			}
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if line == "replace (" {
			inReplaceBlock = true
			continue
		}
		if line == ")" {
			inRequireBlock = false
			inReplaceBlock = false
			continue
		}

		if strings.HasPrefix(line, "require ") && !inRequireBlock {
			requireLine := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			req, ok := parseGoModRequireLine(requireLine)
			if ok {
				parsed.Requires = append(parsed.Requires, req)
			}
			continue
		}

		if strings.HasPrefix(line, "replace ") && !inReplaceBlock {
			replaceLine := strings.TrimSpace(strings.TrimPrefix(line, "replace "))
			rep, ok := parseGoModReplaceLine(replaceLine)
			if ok {
				parsed.Replaces = append(parsed.Replaces, rep)
			}
			continue
		}

		if inRequireBlock {
			req, ok := parseGoModRequireLine(line)
			if ok {
				parsed.Requires = append(parsed.Requires, req)
			}
			continue
		}

		if inReplaceBlock {
			rep, ok := parseGoModReplaceLine(line)
			if ok {
				parsed.Replaces = append(parsed.Replaces, rep)
			}
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, domain.NewAppError(domain.CodeReadError, "Could not parse go.mod", err)
	}

	if parsed.ModulePath == "" {
		return nil, domain.NewAppError(domain.CodeInvalidJSON, "go.mod does not contain a valid module declaration", fmt.Errorf("line %d", lineNo))
	}

	sort.SliceStable(parsed.Requires, func(i, j int) bool {
		if parsed.Requires[i].Module != parsed.Requires[j].Module {
			return parsed.Requires[i].Module < parsed.Requires[j].Module
		}
		return parsed.Requires[i].Version < parsed.Requires[j].Version
	})

	return parsed, nil
}

func (p *GoModParser) BuildDirectDependencies(parsed *goMod, includeDev bool) []domain.DirectDependency {
	deps := make([]domain.DirectDependency, 0, len(parsed.Requires))
	for _, req := range parsed.Requires {
		scope := "require"
		if req.Indirect {
			scope = "require-indirect"
		}
		deps = append(deps, domain.DirectDependency{
			Name:              req.Module,
			VersionConstraint: req.Version,
			Scope:             scope,
		})
	}
	return deps
}

func (p *GoModParser) BuildAuditFindings(parsed *goMod, hasGoSum bool) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)

	if !hasGoSum {
		findings = append(findings, domain.AuditFinding{
			ID:         "MISSING_LOCKFILE",
			Title:      "go.sum is missing",
			Severity:   "medium",
			Category:   "supply-chain",
			Message:    "The project does not include go.sum, which reduces dependency reproducibility and integrity guarantees.",
			Confidence: "high",
		})
	}

	for _, req := range parsed.Requires {
		lower := strings.ToLower(strings.TrimSpace(req.Version))
		if lower == "latest" || lower == "master" || lower == "main" || strings.Contains(lower, "-0.") {
			findings = append(findings, domain.AuditFinding{
				ID:         "UNSAFE_VERSION_CONSTRAINT",
				Title:      "Dependency uses a potentially unstable version reference",
				Severity:   "medium",
				Category:   "supply-chain",
				Package:    req.Module,
				Scope:      "require",
				Message:    fmt.Sprintf("Version %q may track unstable or pseudo-version content.", req.Version),
				Confidence: "medium",
			})
		}
	}

	for _, rep := range parsed.Replaces {
		if isLocalReplaceTarget(rep.NewTarget) || isRemoteReplaceTarget(rep.NewTarget) {
			findings = append(findings, domain.AuditFinding{
				ID:         "RISKY_REPLACE_DIRECTIVE",
				Title:      "go.mod replace directive points to non-registry source",
				Severity:   "high",
				Category:   "supply-chain",
				Package:    rep.OldModule,
				Scope:      "replace",
				Message:    fmt.Sprintf("Replace directive routes %q to %q.", rep.OldModule, rep.NewTarget),
				Confidence: "high",
			})
		}
	}

	sortAuditFindings(findings)
	return findings
}

func parseGoModRequireLine(line string) (goModRequire, bool) {
	trimmed := stripGoModComment(line)
	if trimmed == "" {
		return goModRequire{}, false
	}

	parts := strings.Fields(trimmed)
	if len(parts) < 2 {
		return goModRequire{}, false
	}

	req := goModRequire{Module: parts[0], Version: parts[1]}
	if strings.Contains(line, "// indirect") {
		req.Indirect = true
	}
	return req, true
}

func parseGoModReplaceLine(line string) (goModReplace, bool) {
	trimmed := stripGoModComment(line)
	if trimmed == "" {
		return goModReplace{}, false
	}

	parts := strings.Split(trimmed, "=>")
	if len(parts) != 2 {
		return goModReplace{}, false
	}

	left := strings.Fields(strings.TrimSpace(parts[0]))
	right := strings.Fields(strings.TrimSpace(parts[1]))
	if len(left) == 0 || len(right) == 0 {
		return goModReplace{}, false
	}

	rep := goModReplace{OldModule: left[0], NewTarget: right[0]}
	if len(left) > 1 {
		rep.OldVersion = left[1]
	}
	return rep, true
}

func stripGoModComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return strings.TrimSpace(line[:idx])
	}
	return strings.TrimSpace(line)
}

func isLocalReplaceTarget(target string) bool {
	return strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/")
}

func isRemoteReplaceTarget(target string) bool {
	lower := strings.ToLower(target)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "git://") || strings.HasPrefix(lower, "ssh://")
}
