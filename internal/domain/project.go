package domain

// ProjectDetectionResult holds the result of ecosystem detection for a project path.
// Manifests uses actual manifest filenames as keys (e.g. "composer.json", "package.json").
type ProjectDetectionResult struct {
	ProjectPath string          `json:"project_path"`
	Ecosystem   string          `json:"ecosystem"`
	Manifests   map[string]bool `json:"manifests"`
}
