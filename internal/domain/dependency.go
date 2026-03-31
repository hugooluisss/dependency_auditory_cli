package domain

type DirectDependency struct {
	Name              string `json:"name"`
	VersionConstraint string `json:"version_constraint"`
	Scope             string `json:"scope"`
}

type LockedDependency struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Scope           string   `json:"scope"`
	License         []string `json:"license,omitempty"`
	SourceReference string   `json:"source_reference,omitempty"`
	DistReference   string   `json:"dist_reference,omitempty"`
}

type DirectDependenciesResult struct {
	ProjectPath  string             `json:"project_path"`
	Ecosystem    string             `json:"ecosystem"`
	Dependencies []DirectDependency `json:"dependencies"`
}

type LockedDependenciesResult struct {
	ProjectPath  string             `json:"project_path"`
	Ecosystem    string             `json:"ecosystem"`
	Dependencies []LockedDependency `json:"dependencies"`
}
