# Validation

The bundled CycloneDX 1.6 JSON schema and the SPDX license expression schema are embedded in the
package — no network access is required at runtime. Validation always runs; there is no opt-out.

## BSI TR-03183-2 compliance

Every CycloneDX SBOM already includes the BSI TR-03183-2 §5.2.2 component fields: SPDX-classified
licences (`license.id` / `expression`, falling back to `LicenseRef-*` or a plain `name` when no
SPDX match exists), the `bsi:component:filename`, `bsi:component:executable`,
`bsi:component:archive` and `bsi:component:structured` properties, and a `compositions` entry
marking dependency-completeness as `unknown` (resolution may drop unsatisfied/virtual
dependencies).

Pass `--bsi-tr-compliant` to additionally check the produced SBOM against the BSI TR-03183-2
v2.1.0 data-field requirements: SBOM/component creator contact info (e-mail or URL), SPDX-only
licences, SHA-512 hashes of deployable components, the properties above, and absence of
vulnerability data. This is opt-in because not every environment can supply all required data
(e.g. a SHA-512 for every package, or a maintainer e-mail for every component) — the check
reports exactly what's missing.

This check is **advisory**: findings are printed to stderr as a compliance report, but the
SBOM is still written even if some components don't pass. On a real system, packages with
license metadata that isn't expressible as an SPDX identifier/expression (e.g. `"various"`,
`"public-domain"`) will reliably show up here — the report tells you exactly which components
and fields fall short of full compliance so you can fix what's in your control and document
the rest. Schema validation (always on, not gated by this flag) remains fatal — that catches
structural bugs in the SBOM itself.
