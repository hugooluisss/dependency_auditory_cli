package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hugooluisss/dependency_auditory_cli/internal/domain"
)

const (
	defaultBaseURL   = "https://api.osv.dev"
	queryBatchPath   = "/v1/querybatch"
	vulnPathPrefix   = "/v1/vulns/"
	defaultUserAgent = "depguard/0.1 (+https://github.com/hugooluisss/dependency_auditory_cli)"
	queryBatchSize   = 100
)

var numericScorePattern = regexp.MustCompile(`^\d{1,2}(\.\d+)?$`)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	return NewClientWithBaseURL(httpClient, defaultBaseURL)
}

func NewClientWithBaseURL(httpClient *http.Client, baseURL string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

type queryBatchRequest struct {
	Queries []queryRequest `json:"queries"`
}

type queryRequest struct {
	Package   packageRef `json:"package"`
	Version   string     `json:"version,omitempty"`
	PageToken string     `json:"page_token,omitempty"`
}

type packageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryBatchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns         []vulnerabilityRef `json:"vulns"`
	NextPageToken string             `json:"next_page_token"`
}

type vulnerabilityRef struct {
	ID string `json:"id"`
}

type vulnerabilityDetails struct {
	ID               string                        `json:"id"`
	Summary          string                        `json:"summary"`
	Details          string                        `json:"details"`
	Aliases          []string                      `json:"aliases"`
	Published        string                        `json:"published"`
	Modified         string                        `json:"modified"`
	References       []vulnerabilityLink           `json:"references"`
	Affected         []affectedPackageEntry        `json:"affected"`
	Severity         []severityEntry               `json:"severity"`
	DatabaseSpecific vulnerabilityDatabaseSpecific `json:"database_specific"`
}

type vulnerabilityLink struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type severityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type affectedPackageEntry struct {
	EcosystemSpecific ecosystemSpecific `json:"ecosystem_specific"`
	DatabaseSpecific  ecosystemSpecific `json:"database_specific"`
}

type ecosystemSpecific struct {
	Severity string `json:"severity"`
}

type vulnerabilityDatabaseSpecific struct {
	Severity string `json:"severity"`
}

func (c *Client) BuildAuditFindings(ctx context.Context, osvEcosystem string, deps []domain.LockedDependency) ([]domain.AuditFinding, error) {
	ecosystem := strings.TrimSpace(osvEcosystem)
	if ecosystem == "" {
		return nil, fmt.Errorf("osv ecosystem must not be empty")
	}

	queries := make([]queryRequest, 0, len(deps))
	queryDeps := make([]domain.LockedDependency, 0, len(deps))
	for _, dep := range deps {
		if strings.TrimSpace(dep.Name) == "" || strings.TrimSpace(dep.Version) == "" {
			continue
		}
		queries = append(queries, queryRequest{
			Package: packageRef{
				Name:      dep.Name,
				Ecosystem: ecosystem,
			},
			Version: dep.Version,
		})
		queryDeps = append(queryDeps, dep)
	}

	if len(queries) == 0 {
		return nil, nil
	}

	detailCache := make(map[string]vulnerabilityDetails)
	findings := make([]domain.AuditFinding, 0)

	for start := 0; start < len(queries); start += queryBatchSize {
		end := start + queryBatchSize
		if end > len(queries) {
			end = len(queries)
		}

		results, err := c.queryBatch(ctx, queries[start:end])
		if err != nil {
			return nil, err
		}

		for idx, result := range results {
			dep := queryDeps[start+idx]
			for _, vuln := range result.Vulns {
				details, ok := detailCache[vuln.ID]
				if !ok {
					details, err = c.getVulnerability(ctx, vuln.ID)
					if err != nil {
						return nil, err
					}
					detailCache[vuln.ID] = details
				}
				findings = append(findings, mapFinding(dep, details))
			}
		}
	}

	sortFindings(findings)
	return findings, nil
}

func (c *Client) queryBatch(ctx context.Context, queries []queryRequest) ([]queryResult, error) {
	aggregated := make([]queryResult, len(queries))
	pendingQueries := append([]queryRequest(nil), queries...)
	pendingIndexes := make([]int, len(queries))
	for i := range queries {
		pendingIndexes[i] = i
	}

	for len(pendingQueries) > 0 {
		response, err := c.postQueryBatch(ctx, pendingQueries)
		if err != nil {
			return nil, err
		}
		if len(response.Results) != len(pendingQueries) {
			return nil, fmt.Errorf("osv querybatch returned %d results for %d queries", len(response.Results), len(pendingQueries))
		}

		nextQueries := make([]queryRequest, 0)
		nextIndexes := make([]int, 0)
		for i, result := range response.Results {
			originalIndex := pendingIndexes[i]
			aggregated[originalIndex].Vulns = append(aggregated[originalIndex].Vulns, result.Vulns...)
			if result.NextPageToken != "" {
				nextQuery := pendingQueries[i]
				nextQuery.PageToken = result.NextPageToken
				nextQueries = append(nextQueries, nextQuery)
				nextIndexes = append(nextIndexes, originalIndex)
			}
		}

		pendingQueries = nextQueries
		pendingIndexes = nextIndexes
	}

	return aggregated, nil
}

func (c *Client) postQueryBatch(ctx context.Context, queries []queryRequest) (*queryBatchResponse, error) {
	body, err := json.Marshal(queryBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marshal osv querybatch request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+queryBatchPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build osv querybatch request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", defaultUserAgent)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request osv querybatch: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("osv querybatch returned status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed queryBatchResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode osv querybatch response: %w", err)
	}

	return &parsed, nil
}

func (c *Client) getVulnerability(ctx context.Context, id string) (vulnerabilityDetails, error) {
	vulnURL := c.baseURL + vulnPathPrefix + url.PathEscape(id)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, vulnURL, nil)
	if err != nil {
		return vulnerabilityDetails{}, fmt.Errorf("build osv vulnerability request: %w", err)
	}
	request.Header.Set("User-Agent", defaultUserAgent)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return vulnerabilityDetails{}, fmt.Errorf("request osv vulnerability %q: %w", id, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return vulnerabilityDetails{}, fmt.Errorf("osv vulnerability %q returned status %d: %s", id, response.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed vulnerabilityDetails
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return vulnerabilityDetails{}, fmt.Errorf("decode osv vulnerability %q: %w", id, err)
	}

	return parsed, nil
}

func mapFinding(dep domain.LockedDependency, vuln vulnerabilityDetails) domain.AuditFinding {
	title := strings.TrimSpace(vuln.Summary)
	if title == "" {
		title = "Known vulnerability affects installed package"
	}

	references := make([]string, 0, len(vuln.References))
	for _, reference := range vuln.References {
		if strings.TrimSpace(reference.URL) != "" {
			references = append(references, reference.URL)
		}
	}

	message := fmt.Sprintf("Installed package %q at version %q is affected by %s.", dep.Name, dep.Version, vuln.ID)
	if len(vuln.Aliases) > 0 {
		message += " Aliases: " + strings.Join(vuln.Aliases, ", ") + "."
	}
	if len(references) > 0 {
		message += " Reference: " + references[0] + "."
	}

	return domain.AuditFinding{
		ID:               vuln.ID,
		Title:            title,
		Severity:         normalizeSeverity(vuln),
		Category:         "known-vulnerability",
		Package:          dep.Name,
		Scope:            dep.Scope,
		InstalledVersion: dep.Version,
		Message:          message,
		Confidence:       "high",
		Aliases:          append([]string(nil), vuln.Aliases...),
		References:       references,
		PublishedAt:      vuln.Published,
	}
}

func normalizeSeverity(vuln vulnerabilityDetails) string {
	for _, affected := range vuln.Affected {
		for _, value := range []string{affected.EcosystemSpecific.Severity, affected.DatabaseSpecific.Severity} {
			severity := strings.ToLower(strings.TrimSpace(value))
			switch severity {
			case "critical", "high", "medium", "low":
				return severity
			}
		}
	}

	for _, severity := range vuln.Severity {
		if mapped, ok := normalizeSeverityScore(severity.Score); ok {
			return mapped
		}
	}

	if mapped, ok := normalizeSeverityScore(vuln.DatabaseSpecific.Severity); ok {
		return mapped
	}

	for _, severity := range vuln.Severity {
		lower := strings.ToLower(severity.Score)
		switch {
		case strings.Contains(lower, "critical"):
			return "critical"
		case strings.Contains(lower, "high"):
			return "high"
		case strings.Contains(lower, "medium"):
			return "medium"
		case strings.Contains(lower, "low"):
			return "low"
		}
	}

	return "medium"
}

func normalizeSeverityScore(raw string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return "", false
	}

	switch lower {
	case "critical", "high", "medium", "low":
		return lower, true
	}

	if !numericScorePattern.MatchString(lower) {
		return "", false
	}

	score, err := strconv.ParseFloat(lower, 64)
	if err != nil || math.IsNaN(score) {
		return "", false
	}

	switch {
	case score >= 9.0:
		return "critical", true
	case score >= 7.0:
		return "high", true
	case score >= 4.0:
		return "medium", true
	case score > 0:
		return "low", true
	default:
		return "low", true
	}
}

func sortFindings(findings []domain.AuditFinding) {
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
		if findings[i].Package != findings[j].Package {
			return findings[i].Package < findings[j].Package
		}
		return findings[i].ID < findings[j].ID
	})
}
