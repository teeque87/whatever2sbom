package validator

import "testing"

// TestSchemaCompiles guards against schema-URL resolver regressions like the
// one where the SPDX stub was registered at https:// but the embedded BOM
// schema's $id is http://, causing CycloneDX's relative spdx.schema.json
// $ref to resolve to a URL the compiler couldn't find.
func TestSchemaCompiles(t *testing.T) {
	v, err := NewCycloneDXSchema()
	if err != nil {
		t.Fatalf("NewCycloneDXSchema() failed: %v", err)
	}
	if v == nil {
		t.Fatal("NewCycloneDXSchema() returned nil")
	}
}

// TestValidateMinimalBOM passes a tiny but valid CycloneDX 1.6 document
// through the validator end-to-end. Ensures the SPDX stub satisfies the
// licenses path without choking the rest of the schema.
func TestValidateMinimalBOM(t *testing.T) {
	v, err := NewCycloneDXSchema()
	if err != nil {
		t.Fatalf("NewCycloneDXSchema() failed: %v", err)
	}

	bom := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"version":      1,
		"metadata": map[string]any{
			"timestamp": "2026-05-29T12:00:00+00:00",
			"component": map[string]any{
				"type":    "operating-system",
				"bom-ref": "os-component",
				"name":    "debian",
			},
		},
		"components": []any{
			map[string]any{
				"type":    "library",
				"bom-ref": "pkg:deb/debian/libfoo@1.0",
				"name":    "libfoo",
				"version": "1.0",
				"purl":    "pkg:deb/debian/libfoo@1.0",
				"licenses": []any{
					map[string]any{"license": map[string]any{"name": "MIT"}},
				},
			},
		},
	}
	if errs := v.Validate(bom); len(errs) > 0 {
		t.Fatalf("expected minimal BOM to validate; got errors: %v", errs)
	}
}
