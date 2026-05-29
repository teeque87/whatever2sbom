// Package formatter renders a slice of model.Packages into a serializable BOM.
//
// Formatters are wire-format-specific (CycloneDX 1.6 today, SPDX 2.3 could be
// added later). They return any (a value that can be json.Marshal'd) so the
// CLI and validator stages are oblivious to the chosen format.
package formatter

import "whatever2sbom/internal/model"

// Formatter renders Packages into a wire-format value.
type Formatter interface {
	Name() string
	SchemaName() string
	SpecVersion() string
	OutputExtension() string
	Format(pkgs []*model.Package) (any, error)
}

// ProductOptions describes the optional product/firmware metadata that the
// CLI passes through to the formatter. Required for BSI TR-03183 compliance.
type ProductOptions struct {
	Name         string
	Version      string
	Type         string // firmware | application | container | device | ...
	Supplier     string // required by CLI — NTIA Supplier Name
	SupplierURLs []string
	PURL         string
	Authors      []string // each "Name <email>" or plain name
}
