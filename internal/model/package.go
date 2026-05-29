// Package model defines the uniform Package representation that every
// collector produces and every enricher / formatter consumes.
package model

// Package is the source-agnostic record describing one installed component.
//
// Not every field is populated by every source. Collectors fill the identity
// and provenance fields; enrichers add hashes, licenses, etc. Fields use
// pointer types (or empty strings) so the JSON encoder can drop unknowns.
type Package struct {
	// Identity
	Name         string
	Version      string
	Architecture string

	// Classification (drives CycloneDX type / scope)
	Section   string
	Priority  string
	Essential string

	// Provenance
	Source     string // source package name
	Origin     string // repository origin (e.g. Ubuntu)
	Maintainer string // "Name <email>" — maps to supplier + contact

	// References
	Homepage string
	Bugs     string

	// Dependency graph
	Depends    string
	PreDepends string
	Provides   string // virtual package names this pkg satisfies

	// Content
	Description string

	// Size
	InstalledSize string // KiB on disk
	Size          string // download size in bytes

	// Hashes (sha1 / sha512 come from apt-cache enrichment)
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string

	// Package metadata
	Filename  string // pool-relative .deb path
	MultiArch string

	// Enriched
	Licenses []string
}
