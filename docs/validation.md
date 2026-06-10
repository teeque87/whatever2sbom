# Validation

## Schema validation (always on)

The bundled CycloneDX 1.6 JSON schema and the SPDX license expression schema are embedded in the
package — no network access is required at runtime. Validation runs on every invocation and is
**fatal**: if the generated document doesn't conform to the schema, whatever2sbom exits with a
non-zero status, prints every validation error to stderr, and does not write the output file.
This catches structural bugs in the SBOM itself (e.g. a malformed PURL or a field that violates
the schema's type/enum constraints) — it does not require `--bsi-tr-compliant`.

## BSI TR-03183-2 compliance

Every CycloneDX SBOM already includes the BSI TR-03183-2 §5.2.2 component fields by default:

- SPDX-classified licenses (`license.id` / `expression`, falling back to `LicenseRef-*` or a plain
  `name` when no SPDX match exists)
- the `bsi:component:filename`, `bsi:component:executable`, `bsi:component:archive` and
  `bsi:component:structured` properties
- a `compositions` entry marking dependency-completeness as `unknown` (resolution may drop
  unsatisfied or virtual dependencies)

### `--bsi-tr-compliant`

Pass `--bsi-tr-compliant` to additionally check the produced SBOM against the BSI TR-03183-2
v2.1.0 data-field requirements:

- SBOM and component creator contact info (e-mail or URL)
- SPDX-only licenses (no `LicenseRef-*` or free-form `name` fallbacks)
- SHA-512 hashes for all deployable components
- the §5.2.2 properties listed above
- absence of vulnerability data

This check is **opt-in** because not every environment can supply all of this data — for example,
a SHA-512 for every package, or a maintainer e-mail for every component. The check is also
**advisory**: findings are printed to stderr as a compliance report and written in full to
`<output>.bsi-report.txt`, but the SBOM is still written even if some components don't pass.

On a real system, packages whose license metadata isn't expressible as an SPDX
identifier/expression (e.g. `"various"`, `"public-domain"`) will reliably show up here. The report
tells you exactly which components and fields fall short, so you can fix what's in your control
and document the rest.

```text
BSI TR-03183-2 compliance: 42 finding(s) (full list written to acmefw.bsi-report.txt):
  [  31x] component missing SHA-512 hash
  [   8x] component license is not SPDX-expressible (LicenseRef-*)
  [   3x] component missing supplier contact (email or URL)
```

Schema validation (always on, not gated by this flag) remains separate and fatal — it catches
structural bugs, while `--bsi-tr-compliant` reports on data completeness.
