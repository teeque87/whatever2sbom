// Package validator runs the produced BOM against its declared schema.
//
// Validation is always part of the pipeline — there is no opt-out flag, by
// design. Failing validation aborts the run with a non-zero exit code.
package validator

// Validator checks a BOM value against a schema.
type Validator interface {
	Name() string
	SchemaName() string
	SpecVersion() string
	// Validate returns one human-readable string per violation. An empty
	// slice means the BOM validated cleanly.
	Validate(bom any) []string
}
