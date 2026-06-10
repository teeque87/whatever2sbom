# `pip`

Scans a Python virtualenv via `importlib.metadata` (`--system pip`) — no network access and no
parsing of `requirements.txt` (which can't express a real dependency graph).

## Venv discovery

If `--venv-dir` isn't given, the venv is auto-detected by looking for a `pyvenv.cfg` file (the
canonical [PEP 405](https://peps.python.org/pep-0405/) marker, independent of directory naming):

1. `--project-dir` itself, if it directly contains `pyvenv.cfg`.
2. Otherwise, any single immediate subdirectory of `--project-dir` containing `pyvenv.cfg`.

Multiple candidates or none found raise an error telling you to pass `--venv-dir` explicitly.

`$VIRTUAL_ENV` is **not** consulted — whatever2sbom itself is often run from inside its own
virtualenv, which would otherwise shadow the *target* project's venv.

## Collection

Every installed distribution under the venv's `site-packages`, with:

- **PURLs** — `pkg:pypi/<name>@<version>`, with `<name>` PEP 503 normalized (lowercase, `-_.`
  collapsed to `-`).
- **Homepage / issue tracker** — from `Home-page`, falling back to a `Project-URL` entry labelled
  "Homepage"/"Documentation"/"Issues"/"Bug Tracker"/etc.
- **`bsi:component:executable`** — `executable` if the distribution declares a `console_scripts`
  entry point, else `non-executable`.

## License resolution

Tried in order, first match wins:

1. PEP 639 `License-Expression` (SPDX expression).
2. The legacy `License` field (if not `"UNKNOWN"`).
3. An unambiguous `License :: ...` Trove classifier (e.g. "MIT License" → `MIT`). Ambiguous
   classifiers like "BSD License" are skipped — they cover multiple SPDX variants.
4. Standard license boilerplate recognized in a bundled `License-File`
   (MIT / Apache-2.0 / BSD-2-Clause / BSD-3-Clause / ISC / MPL-2.0 / Unlicense).

If none of these match, `licenses` is omitted for that component.

## Dependency graph

Built from each distribution's `Requires-Dist` entries (`dist.requires`), cross-referenced
against the other installed packages:

- Requirements gated on `extra == "..."` (optional/dev/test extras — including a package's *own*
  extras, e.g. `pytest; extra == "testing"` on `pluggy`) are **excluded entirely**. There's no
  reliable way to tell from installed metadata alone whether an extra was actually requested, and
  guessing "yes" produces false edges and dependency cycles.
- Other environment markers (`python_version`, `sys_platform`, …) are evaluated against the
  *running* interpreter, not the scanned venv's.

## Product metadata

`--product-name`, `--product-version`, `--product-type`, etc. come **only from the CLI
arguments** — whatever2sbom does not read `pyproject.toml` (or any other project file) for product
metadata.

**`--product-name` is required for `--system pip`.** Unlike `dpkg`, a scanned virtualenv isn't the
host OS, so there's no accurate fallback for `metadata.component` — the CLI exits with an error if
`--product-name` is missing.

If `--product-type` is omitted, the product defaults to type `application` (vs. `operating-system`
for `dpkg`) — a Python project is an application, not an operating system or firmware image.

### Scanning a project's own venv

If `--product-name` matches one of the scanned packages (e.g. you're scanning a project's own
venv, which includes the project itself, normalized PEP-503-ish for comparison), that package is:

- excluded from `metadata.component`'s dependency list as a self-reference, and
- used as the source of the root's `dependsOn` — i.e. the root depends on exactly that package's
  own resolved `Requires-Dist`, not on every installed package.

## Options

| Option | Description |
|---|---|
| `--venv-dir PATH` | Path to the virtualenv to scan. Must contain `pyvenv.cfg`. |
| `--project-dir PATH` | Project root to search for a virtualenv when `--venv-dir` is not given (default: current directory). |

## Example

```bash
whatever2sbom --system pip \
  --product-name myproject \
  --product-version "1.2.3" \
  --product-supplier "Acme GmbH" \
  -o myproject.cdx.json
```

If the venv can't be auto-detected (e.g. multiple venvs under the project, or it lives elsewhere):

```bash
whatever2sbom --system pip --venv-dir /path/to/.venv \
  --product-name myproject --product-supplier "Acme GmbH"
```
