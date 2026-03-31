package domain

const EcosystemPHPComposer = "php-composer"

type Manifests struct {
	ComposerJSON bool `json:"composer_json"`
	ComposerLock bool `json:"composer_lock"`
}

type ProjectDetectionResult struct {
	ProjectPath string    `json:"project_path"`
	Ecosystem   string    `json:"ecosystem"`
	Manifests   Manifests `json:"manifests"`
}
