# Releasing

The package version is **not** stored in `pyproject.toml`. It's derived from git tags via
[`setuptools_scm`](https://setuptools-scm.readthedocs.io/): `pyproject.toml` declares
`dynamic = ["version"]`, and `whatever2sbom.__version__`
([`__init__.py`](https://github.com/teeque87/whatever2sbom/blob/main/src/whatever2sbom/__init__.py))
reads it back from the installed package's metadata at runtime.

## Cutting a release

1. Make sure `main` is in the state you want to release.
2. Tag it with a `v<major>.<minor>.<patch>` tag and push the tag:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. Pushing a `v*` tag triggers
   [`.github/workflows/release.yml`](https://github.com/teeque87/whatever2sbom/blob/main/.github/workflows/release.yml),
   which builds the wheel, builds and deploys the docs site, and publishes a GitHub Release with
   the wheel attached.

The tag `v0.2.0` produces package version `0.2.0` — the leading `v` is stripped by
`setuptools_scm`. An untagged commit (e.g. a local editable install, or a manual workflow run on
`main`) gets a development version like `0.2.1.dev3+gabcdef0`, so builds are always
distinguishable from a tagged release without any manual bookkeeping.

## Versioning scheme

Use [SemVer](https://semver.org/): `MAJOR.MINOR.PATCH`. Bump `MAJOR` for breaking CLI/output
changes, `MINOR` for new systems/schemas/options, `PATCH` for fixes that don't change behavior
otherwise.
