package gomod

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
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("github.com/gin-gonic/gin v1.7.7 h1:abc\n"), 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}

	scanner := NewScanner(filesystem.NewReader(), fakeVulnerabilitySource{
		findings: []domain.AuditFinding{{
			ID:               "GO-remote",
			Title:            "Known vulnerability affects installed package",
			Severity:         "high",
			Category:         "known-vulnerability",
			Package:          "github.com/gin-gonic/gin",
			Scope:            "go.sum",
			InstalledVersion: "v1.7.7",
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
	if findings[0].ID != "GO-remote" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
}
