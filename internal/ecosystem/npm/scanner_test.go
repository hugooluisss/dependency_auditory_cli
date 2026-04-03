package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
	"github.com/hugooluisss/dependency_auditory_cli/internal/infra/filesystem"
)

type fakeVulnerabilitySource struct {
	findings []domain.AuditFinding
	err      error
}

func (f fakeVulnerabilitySource) BuildAuditFindings(ctx context.Context, osvEcosystem string, deps []domain.LockedDependency) ([]domain.AuditFinding, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

func TestScannerBuildAuditFindingsAppendsRemoteResults(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"acme-app","dependencies":{"lodash":"^4.17.0"}}`), 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"name":"lodash","version":"4.17.20","license":"MIT","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz","integrity":"sha512-abc"}}}`), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	scanner := NewScanner(filesystem.NewReader(), fakeVulnerabilitySource{
		findings: []domain.AuditFinding{{
			ID:               "GHSA-npm-remote",
			Title:            "Known vulnerability affects installed package",
			Severity:         "high",
			Category:         "known-vulnerability",
			Package:          "lodash",
			Scope:            "dependencies",
			InstalledVersion: "4.17.20",
			Message:          "Installed package is vulnerable.",
			Confidence:       "high",
		}},
	})

	findings, err := scanner.BuildAuditFindings(root)
	if err != nil {
		t.Fatalf("BuildAuditFindings returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "GHSA-npm-remote" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
}
