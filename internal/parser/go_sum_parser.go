package parser

import (
	"bufio"
	"sort"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

type goSumEntry struct {
	Module  string
	Version string
	Hash    string
}

type goSum struct {
	Entries []goSumEntry
}

type GoSumParser struct{}

func NewGoSumParser() *GoSumParser {
	return &GoSumParser{}
}

func (p *GoSumParser) Parse(raw []byte) (*goSum, error) {
	parsed := &goSum{Entries: make([]goSumEntry, 0)}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}

		version := strings.TrimSuffix(parts[1], "/go.mod")
		parsed.Entries = append(parsed.Entries, goSumEntry{
			Module:  parts[0],
			Version: version,
			Hash:    parts[2],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, domain.NewAppError(domain.CodeReadError, "Could not parse go.sum", err)
	}

	return parsed, nil
}

func (p *GoSumParser) BuildLockedDependencies(parsed *goSum) []domain.LockedDependency {
	type merged struct {
		module  string
		version string
		hash    string
	}

	mergedByKey := map[string]merged{}
	for _, entry := range parsed.Entries {
		key := entry.Module + "@" + entry.Version
		current := mergedByKey[key]
		if current.module == "" {
			mergedByKey[key] = merged{module: entry.Module, version: entry.Version, hash: entry.Hash}
			continue
		}
		if current.hash == "" && entry.Hash != "" {
			current.hash = entry.Hash
			mergedByKey[key] = current
		}
	}

	keys := make([]string, 0, len(mergedByKey))
	for key := range mergedByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	deps := make([]domain.LockedDependency, 0, len(keys))
	for _, key := range keys {
		item := mergedByKey[key]
		deps = append(deps, domain.LockedDependency{
			Name:          item.module,
			Version:       item.version,
			Scope:         "go.sum",
			DistReference: item.hash,
		})
	}

	return deps
}

func (p *GoSumParser) BuildAuditFindings(parsed *goSum) []domain.AuditFinding {
	findings := make([]domain.AuditFinding, 0)
	deps := p.BuildLockedDependencies(parsed)

	for _, dep := range deps {
		if dep.DistReference == "" {
			findings = append(findings, domain.AuditFinding{
				ID:         "MISSING_SOURCE_REFERENCE",
				Title:      "Locked module has no checksum reference",
				Severity:   "low",
				Category:   "traceability",
				Package:    dep.Name,
				Scope:      dep.Scope,
				Message:    "go.sum entry does not include checksum metadata.",
				Confidence: "medium",
			})
		}
	}

	sortAuditFindings(findings)
	return findings
}
