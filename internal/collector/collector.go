// Package collector defines the Collector interface and the dpkg implementation.
//
// A Collector walks one source of truth (the dpkg database, an `requirements.txt`,
// an OCI image manifest, …) and returns a slice of model.Package.
package collector

import "whatever2sbom/internal/model"

// Collector turns an installed-package source into a slice of Packages.
type Collector interface {
	// Name is the short identifier shown in logs (e.g. "dpkg").
	Name() string
	// Collect runs the underlying tool and returns one Package per installed item.
	Collect() ([]*model.Package, error)
}
