package validator

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// The CycloneDX 1.6 JSON schema is bundled into the binary at compile time.
//
//go:embed schemas/bom-1.6.schema.json
var cycloneDX16Schema []byte

// CycloneDXSchema validates against the embedded CycloneDX 1.6 JSON schema.
type CycloneDXSchema struct {
	schema *jsonschema.Schema
}

// NewCycloneDXSchema compiles the embedded schema once at construction.
//
// CycloneDX's official schema references spdx.schema.json — a separate file
// that ships as a stub here (any string passes) so the rest of the schema
// still validates without an external resolver.
func NewCycloneDXSchema() (*CycloneDXSchema, error) {
	const (
		bomURL  = "https://cyclonedx.org/schema/bom-1.6.schema.json"
		spdxURL = "https://cyclonedx.org/schema/spdx.schema.json"
	)
	stub := []byte(`{"type":"string"}`)

	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7

	if err := compiler.AddResource(bomURL, bytes.NewReader(cycloneDX16Schema)); err != nil {
		return nil, fmt.Errorf("registering CycloneDX schema: %w", err)
	}
	if err := compiler.AddResource(spdxURL, bytes.NewReader(stub)); err != nil {
		return nil, fmt.Errorf("registering SPDX stub schema: %w", err)
	}

	sch, err := compiler.Compile(bomURL)
	if err != nil {
		return nil, fmt.Errorf("compiling CycloneDX schema: %w", err)
	}
	return &CycloneDXSchema{schema: sch}, nil
}

// Name implements Validator.
func (*CycloneDXSchema) Name() string { return "cyclonedx-1.6-jsonschema" }

// SchemaName implements Validator.
func (*CycloneDXSchema) SchemaName() string { return "cyclonedx" }

// SpecVersion implements Validator.
func (*CycloneDXSchema) SpecVersion() string { return "1.6" }

// Validate marshals the BOM to JSON and runs it through the compiled schema.
//
// We round-trip through JSON so that the schema validator sees the same
// canonical form that gets written to disk — any encoder-side decisions
// (omitempty, key ordering) participate in validation.
func (v *CycloneDXSchema) Validate(bom any) []string {
	raw, err := json.Marshal(bom)
	if err != nil {
		return []string{fmt.Sprintf("(root): cannot marshal BOM to JSON: %v", err)}
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return []string{fmt.Sprintf("(root): cannot decode BOM JSON: %v", err)}
	}

	if err := v.schema.Validate(decoded); err != nil {
		errs := collectErrors(err)
		slog.Warn("schema validation failed", "errors", len(errs))
		return errs
	}
	slog.Info("schema validation passed")
	return nil
}

// collectErrors walks a jsonschema.ValidationError and produces one
// "path: message" line per leaf violation. Mirrors the Python validator's
// dot-joined absolute_path style.
func collectErrors(err error) []string {
	var ve *jsonschema.ValidationError
	if !asValidation(err, &ve) {
		return []string{err.Error()}
	}
	var out []string
	walkValidation(ve, &out)
	return out
}

func asValidation(err error, target **jsonschema.ValidationError) bool {
	if v, ok := err.(*jsonschema.ValidationError); ok {
		*target = v
		return true
	}
	return false
}

func walkValidation(ve *jsonschema.ValidationError, out *[]string) {
	if len(ve.Causes) == 0 {
		path := strings.TrimPrefix(ve.InstanceLocation, "/")
		path = strings.ReplaceAll(path, "/", ".")
		if path == "" {
			path = "(root)"
		}
		*out = append(*out, fmt.Sprintf("%s: %s", path, ve.Message))
		return
	}
	for _, c := range ve.Causes {
		walkValidation(c, out)
	}
}
