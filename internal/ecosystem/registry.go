package ecosystem

import "github.com/hugooluisss/dependency_auditory_cli/internal/domain"

// Registry holds the ordered list of registered ecosystem scanners.
// Scanners are evaluated in registration order; the first match wins.
type Registry struct {
	scanners []Scanner
}

// NewRegistry returns a Registry pre-populated with the given scanners.
// To support a new ecosystem, add its scanner here in cmd/root.go's newRegistry().
func NewRegistry(scanners ...Scanner) *Registry {
	return &Registry{scanners: scanners}
}

// Detect iterates registered scanners and returns the first one that
// recognises path, together with its manifest presence map.
// Returns PROJECT_NOT_SUPPORTED when no scanner matches.
func (r *Registry) Detect(path string) (Scanner, map[string]bool, error) {
	for _, s := range r.scanners {
		ok, manifests, err := s.Detect(path)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			return s, manifests, nil
		}
	}
	return nil, nil, domain.NewAppError(
		domain.CodeProjectNotSupported,
		"No supported ecosystem was detected in the target path",
		nil,
	)
}
