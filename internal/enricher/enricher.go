// Package enricher defines the Enricher interface and the built-in enrichers
// (apt-cache hash lookup, /usr/share/doc copyright extraction).
package enricher

import "whatever2sbom/internal/model"

// Enricher mutates a slice of Packages in place and returns it.
//
// Enrichers run sequentially as a chain. They must be safe to skip — if their
// data source is unavailable (e.g. apt-cache not installed) they should log
// and return the input unchanged.
type Enricher interface {
	Name() string
	Enrich(pkgs []*model.Package) ([]*model.Package, error)
}
