package parser

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type lockReference struct {
	Reference string `json:"reference"`
}

type lockPackage struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	License []string      `json:"license"`
	Source  lockReference `json:"source"`
	Dist    lockReference `json:"dist"`
}

type composerLock struct {
	Packages    []lockPackage `json:"packages"`
	PackagesDev []lockPackage `json:"packages-dev"`
}

type ComposerLockParser struct{}

func NewComposerLockParser() *ComposerLockParser {
	return &ComposerLockParser{}
}

func (p *ComposerLockParser) Parse(raw []byte) (*composerLock, error) {
	var parsed composerLock
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, domain.NewAppError(domain.CodeInvalidJSON, "composer.lock contains invalid JSON", err)
	}
	return &parsed, nil
}

func (p *ComposerLockParser) BuildLockedDependencies(parsed *composerLock) []domain.LockedDependency {
	deps := make([]domain.LockedDependency, 0, len(parsed.Packages)+len(parsed.PackagesDev))

	for _, pkg := range parsed.Packages {
		deps = append(deps, mapLockPackage(pkg, "packages"))
	}
	for _, pkg := range parsed.PackagesDev {
		deps = append(deps, mapLockPackage(pkg, "packages-dev"))
	}

	return deps
}

func mapLockPackage(pkg lockPackage, scope string) domain.LockedDependency {
	dep := domain.LockedDependency{
		Name:    pkg.Name,
		Version: pkg.Version,
		Scope:   scope,
	}

	if len(pkg.License) > 0 {
		dep.License = pkg.License
	}
	if pkg.Source.Reference != "" {
		dep.SourceReference = pkg.Source.Reference
	}
	if pkg.Dist.Reference != "" {
		dep.DistReference = pkg.Dist.Reference
	}

	return dep
}

func (p *ComposerLockParser) BuildAuditFindings(parsed *composerLock) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)

	for _, pkg := range parsed.Packages {
		findings = append(findings, packageFindings(pkg, "packages")...)
	}
	for _, pkg := range parsed.PackagesDev {
		findings = append(findings, packageFindings(pkg, "packages-dev")...)
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

func packageFindings(pkg lockPackage, scope string) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)

	if len(pkg.License) == 0 {
		findings = append(findings, domain.AuditFinding{
			ID:         "MISSING_LICENSE_METADATA",
			Title:      "Locked package has no declared license",
			Severity:   "low",
			Category:   "metadata",
			Package:    pkg.Name,
			Scope:      scope,
			Message:    "No license field found for the package in composer.lock.",
			Confidence: "high",
		})
	}

	if pkg.Source.Reference == "" && pkg.Dist.Reference == "" {
		findings = append(findings, domain.AuditFinding{
			ID:         "MISSING_SOURCE_REFERENCE",
			Title:      "Locked package has no source or dist reference",
			Severity:   "low",
			Category:   "traceability",
			Package:    pkg.Name,
			Scope:      scope,
			Message:    fmt.Sprintf("Package %q does not expose source.reference or dist.reference.", pkg.Name),
			Confidence: "medium",
		})
	}

	return findings
}
