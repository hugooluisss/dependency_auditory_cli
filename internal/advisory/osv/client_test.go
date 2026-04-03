package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

func TestClientBuildAuditFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case queryBatchPath:
			var payload queryBatchRequest
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if len(payload.Queries) != 2 {
				t.Fatalf("expected 2 queries, got %d", len(payload.Queries))
			}
			_ = json.NewEncoder(writer).Encode(queryBatchResponse{
				Results: []queryResult{
					{Vulns: []vulnerabilityRef{{ID: "GHSA-1234"}}},
					{},
				},
			})
		case vulnPathPrefix + "GHSA-1234":
			_ = json.NewEncoder(writer).Encode(vulnerabilityDetails{
				ID:        "GHSA-1234",
				Summary:   "Remote code execution in package",
				Aliases:   []string{"CVE-2026-1111"},
				Published: "2026-04-01T00:00:00Z",
				References: []vulnerabilityLink{
					{Type: "ADVISORY", URL: "https://example.com/advisories/GHSA-1234"},
				},
				Affected: []affectedPackageEntry{
					{EcosystemSpecific: ecosystemSpecific{Severity: "HIGH"}},
				},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithBaseURL(server.Client(), server.URL)
	findings, err := client.BuildAuditFindings(context.Background(), "Packagist", []domain.LockedDependency{
		{Name: "vendor/package", Version: "1.2.3", Scope: "packages"},
		{Name: "vendor/clean", Version: "4.5.6", Scope: "packages-dev"},
	})
	if err != nil {
		t.Fatalf("BuildAuditFindings returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.ID != "GHSA-1234" {
		t.Fatalf("unexpected finding ID: %s", finding.ID)
	}
	if finding.Package != "vendor/package" {
		t.Fatalf("unexpected finding package: %s", finding.Package)
	}
	if finding.InstalledVersion != "1.2.3" {
		t.Fatalf("unexpected installed version: %s", finding.InstalledVersion)
	}
	if finding.Severity != "high" {
		t.Fatalf("unexpected severity: %s", finding.Severity)
	}
	if len(finding.References) != 1 || finding.References[0] != "https://example.com/advisories/GHSA-1234" {
		t.Fatalf("unexpected references: %#v", finding.References)
	}
}

func TestNormalizeSeverityUsesDatabaseSpecificNumericScore(t *testing.T) {
	severity := normalizeSeverity(vulnerabilityDetails{
		DatabaseSpecific: vulnerabilityDatabaseSpecific{Severity: "9.8"},
	})
	if severity != "critical" {
		t.Fatalf("expected critical severity, got %q", severity)
	}
}

func TestNormalizeSeverityUsesAffectedDatabaseSpecificLabel(t *testing.T) {
	severity := normalizeSeverity(vulnerabilityDetails{
		Affected: []affectedPackageEntry{{
			DatabaseSpecific: ecosystemSpecific{Severity: "HIGH"},
		}},
	})
	if severity != "high" {
		t.Fatalf("expected high severity, got %q", severity)
	}
}
