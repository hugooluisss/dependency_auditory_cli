package parser

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type packageLockDependency struct {
	Version      string                           `json:"version"`
	Resolved     string                           `json:"resolved"`
	Integrity    string                           `json:"integrity"`
	Dev          bool                             `json:"dev"`
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

type packageEntry struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	License   string `json:"license"`
	Name      string `json:"name"`
}

type packageLock struct {
	LockfileVersion int                              `json:"lockfileVersion"`
	Dependencies    map[string]packageLockDependency `json:"dependencies"`
	Packages        map[string]packageEntry          `json:"packages"`
}

type PackageLockParser struct{}

func NewPackageLockParser() *PackageLockParser {
	return &PackageLockParser{}
}

func (p *PackageLockParser) Parse(raw []byte) (*packageLock, error) {
	var parsed packageLock
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, domain.NewAppError(domain.CodeInvalidJSON, "package-lock.json contains invalid JSON", err)
	}

	if parsed.Dependencies == nil {
		parsed.Dependencies = map[string]packageLockDependency{}
	}
	if parsed.Packages == nil {
		parsed.Packages = map[string]packageEntry{}
	}

	return &parsed, nil
}

func (p *PackageLockParser) BuildLockedDependencies(parsed *packageLock) []domain.LockedDependency {
	deps := make([]domain.LockedDependency, 0)
	seen := map[string]struct{}{}

	for path, pkg := range parsed.Packages {
		if path == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = packageNameFromPath(path)
		}
		if name == "" {
			continue
		}

		key := name + "@" + pkg.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		dep := domain.LockedDependency{
			Name:    name,
			Version: pkg.Version,
			Scope:   npmScope(pkg.Dev),
		}
		if pkg.License != "" {
			dep.License = []string{pkg.License}
		}
		if pkg.Resolved != "" {
			dep.SourceReference = pkg.Resolved
		}
		if pkg.Integrity != "" {
			dep.DistReference = pkg.Integrity
		}
		deps = append(deps, dep)
	}

	if len(deps) == 0 {
		for _, name := range sortedPackageLockKeys(parsed.Dependencies) {
			walkPackageLockDependency(name, parsed.Dependencies[name], seen, &deps)
		}
	}

	sort.SliceStable(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		if deps[i].Version != deps[j].Version {
			return deps[i].Version < deps[j].Version
		}
		return deps[i].Scope < deps[j].Scope
	})

	return deps
}

func (p *PackageLockParser) BuildAuditFindings(parsed *packageLock) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	deps := p.BuildLockedDependencies(parsed)

	for _, dep := range deps {
		if len(dep.License) == 0 {
			findings = append(findings, domain.AuditFinding{
				ID:         "MISSING_LICENSE_METADATA",
				Title:      "Locked package has no declared license",
				Severity:   "low",
				Category:   "metadata",
				Package:    dep.Name,
				Scope:      dep.Scope,
				Message:    "No license field found for the package in package-lock.json.",
				Confidence: "medium",
			})
		}

		if dep.SourceReference == "" && dep.DistReference == "" {
			findings = append(findings, domain.AuditFinding{
				ID:         "MISSING_SOURCE_REFERENCE",
				Title:      "Locked package has no resolved URL or integrity hash",
				Severity:   "low",
				Category:   "traceability",
				Package:    dep.Name,
				Scope:      dep.Scope,
				Message:    fmt.Sprintf("Package %q does not expose resolved or integrity fields.", dep.Name),
				Confidence: "medium",
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Scope != findings[j].Scope {
			return findings[i].Scope < findings[j].Scope
		}
		return findings[i].Package < findings[j].Package
	})

	return findings
}

func walkPackageLockDependency(name string, node packageLockDependency, seen map[string]struct{}, out *[]domain.LockedDependency) {
	key := name + "@" + node.Version
	if _, ok := seen[key]; !ok {
		seen[key] = struct{}{}
		dep := domain.LockedDependency{
			Name:    name,
			Version: node.Version,
			Scope:   npmScope(node.Dev),
		}
		if node.Resolved != "" {
			dep.SourceReference = node.Resolved
		}
		if node.Integrity != "" {
			dep.DistReference = node.Integrity
		}
		*out = append(*out, dep)
	}

	for _, childName := range sortedPackageLockKeys(node.Dependencies) {
		walkPackageLockDependency(childName, node.Dependencies[childName], seen, out)
	}
}

func sortedPackageLockKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func npmScope(dev bool) string {
	if dev {
		return "devDependencies"
	}
	return "dependencies"
}

func packageNameFromPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "node_modules/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
