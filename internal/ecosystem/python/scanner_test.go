package python

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
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte(`requests==2.28.0`), 0o600); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "poetry.lock"), []byte("[[package]]\nname = \"requests\"\nversion = \"2.28.0\"\n"), 0o600); err != nil {
		t.Fatalf("write poetry.lock: %v", err)
	}

	scanner := NewScanner(filesystem.NewReader(), fakeVulnerabilitySource{
		findings: []domain.AuditFinding{{
			ID:               "PYSEC-remote",
			Title:            "Known vulnerability affects installed package",
			Severity:         "medium",
			Category:         "known-vulnerability",
			Package:          "requests",
			Scope:            "package",
			InstalledVersion: "2.28.0",
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
	if findings[0].ID != "PYSEC-remote" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
}
