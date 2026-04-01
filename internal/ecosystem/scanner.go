package ecosystem

import "github.com/hugooluisss/dependency_auditory_cli/internal/domain"

// Scanner is the contract every ecosystem must implement.
type Scanner interface {
	Name() string
	Detect(path string) (bool, map[string]bool, error)
	ListDirectDependencies(path string, includeDev bool) ([]domain.DirectDependency, error)
	ListLockedDependencies(path string) ([]domain.LockedDependency, error)
	BuildAuditFindings(path string) ([]domain.AuditFinding, error)
}
