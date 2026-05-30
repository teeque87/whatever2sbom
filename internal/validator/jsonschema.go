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

// All three CycloneDX schemas are bundled at compile time. The bom schema
// $ref's the other two via relative URIs that resolve against its $id —
// they must be registered with the compiler at their canonical $id URLs
// so resolution never falls back to the library's HTTP loader.
//
// Validation is therefore fully offline: no network access at runtime.
var (
	//go:embed schemas/bom-1.6.schema.json
	bomSchema []byte
	//go:embed schemas/spdx.schema.json
	spdxSchema []byte
	//go:embed schemas/jsf-0.82.schema.json
	jsfSchema []byte
)

// Canonical $id URLs declared inside each bundled schema. The bom schema
// references the others via relative URIs that resolve against these IDs.
const (
	bomSchemaURL  = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	spdxSchemaURL = "http://cyclonedx.org/schema/spdx.schema.json"
	jsfSchemaURL  = "http://cyclonedx.org/schema/jsf-0.82.schema.json"
)

// CycloneDXSchema validates against the embedded CycloneDX 1.6 JSON schema.
type CycloneDXSchema struct {
	schema *jsonschema.Schema
}

// NewCycloneDXSchema compiles the bundled schemas once at construction.
// Returns an error if any embedded schema is malformed or any internal
// $ref fails to resolve — both are programmer errors, not user errors.
func NewCycloneDXSchema() (*CycloneDXSchema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7

	resources := []struct {
		url  string
		body []byte
	}{
		{bomSchemaURL, bomSchema},
		{spdxSchemaURL, spdxSchema},
		{jsfSchemaURL, jsfSchema},
	}
	for _, r := range resources {
		if err := compiler.AddResource(r.url, bytes.NewReader(r.body)); err != nil {
			return nil, fmt.Errorf("registering %s: %w", r.url, err)
		}
	}

	sch, err := compiler.Compile(bomSchemaURL)
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
	slog.Info("  ← Validation passed")
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
