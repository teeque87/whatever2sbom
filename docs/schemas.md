# Schemas

`--schema` selects the output document format; `--spec-version` selects which version of that
format's specification to target. The schema is **independent of the system you scan** — any system
(`dpkg`, `npm`, `pip`, …) produces the same kind of document, so the choice here is orthogonal to
`--system`.

| Format | Versions | Notes |
|---|---|---|
| `cyclonedx` | `1.6` | Default. Produces a `.cdx.json` file, validated against the bundled CycloneDX 1.6 JSON schema. |

The chosen schema also fixes the output file extension (`.cdx.json` for CycloneDX) and the default
filename, `sbom_<timestamp>.<ext>`.

Adding a new schema (e.g. SPDX) or a new spec version of an existing one (e.g. CycloneDX 1.7) is
covered in [Extending whatever2sbom](extending.md#adding-a-new-output-schema).

## See also

- [Output format](output.md) — the fields a generated CycloneDX document carries.
- [Validation](validation.md) — how the document is checked against the schema (and, optionally,
  BSI TR-03183-2).
