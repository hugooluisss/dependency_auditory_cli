package composer

import (
	"context"
	"errors"
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
	if err := os.WriteFile(filepath.Join(root, "composer.json"), []byte(`{"name":"acme/app","require":{"vendor/package":"^1.0"}}`), 0o600); err != nil {
		t.Fatalf("write composer.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"1.2.3","license":["MIT"],"source":{"reference":"abc123"}}],"packages-dev":[]}`), 0o600); err != nil {
		t.Fatalf("write composer.lock: %v", err)
	}

	scanner := NewScanner(filesystem.NewReader(), fakeVulnerabilitySource{
		findings: []domain.AuditFinding{{
			ID:               "GHSA-remote",
			Title:            "Known vulnerability affects installed package",
			Severity:         "high",
			Category:         "known-vulnerability",
			Package:          "vendor/package",
			Scope:            "packages",
			InstalledVersion: "1.2.3",
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
	if findings[0].ID != "GHSA-remote" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestScannerBuildAuditFindingsReportsUnavailableSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "composer.json"), []byte(`{"name":"acme/app","require":{"vendor/package":"^1.0"}}`), 0o600); err != nil {
		t.Fatalf("write composer.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"1.2.3","license":["MIT"],"source":{"reference":"abc123"}}],"packages-dev":[]}`), 0o600); err != nil {
		t.Fatalf("write composer.lock: %v", err)
	}

	scanner := NewScanner(filesystem.NewReader(), fakeVulnerabilitySource{err: errors.New("timeout")})
	findings, err := scanner.BuildAuditFindings(root)
	if err != nil {
		t.Fatalf("BuildAuditFindings returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "VULNERABILITY_SOURCE_UNAVAILABLE" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
	if findings[0].Severity != "info" {
		t.Fatalf("unexpected severity: %s", findings[0].Severity)
	}
}
