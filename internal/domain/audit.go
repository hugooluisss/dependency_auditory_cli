package domain

type AuditSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type AuditFinding struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Category         string   `json:"category"`
	Package          string   `json:"package,omitempty"`
	Scope            string   `json:"scope,omitempty"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	Message          string   `json:"message"`
	Confidence       string   `json:"confidence"`
	Aliases          []string `json:"aliases,omitempty"`
	References       []string `json:"references,omitempty"`
	PublishedAt      string   `json:"published_at,omitempty"`
}

type AuditScanResult struct {
	ProjectPath string         `json:"project_path"`
	Ecosystem   string         `json:"ecosystem"`
	Summary     AuditSummary   `json:"summary"`
	Findings    []AuditFinding `json:"findings"`
}
