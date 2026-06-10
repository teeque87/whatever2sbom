"""Unit tests for the CycloneDX formatter's root dependency handling."""

from whatever2sbom.formatters.cyclonedx16 import CycloneDXFormatter
from whatever2sbom.models import PackageRecord


def _pkg(name: str, version: str, deps: list[str] | None = None) -> PackageRecord:
    pkg = PackageRecord(name=name, version=version)
    pkg.bom_ref = f"pkg:pypi/{name.lower()}@{version}"
    pkg.purl = pkg.bom_ref
    pkg.dependency_refs = deps or []
    return pkg


def _formatter(**kwargs) -> CycloneDXFormatter:
    return CycloneDXFormatter(product_supplier="Example Corp", **kwargs)


def test_root_depends_on_all_packages_without_product_name() -> None:
    packages = [_pkg("foo", "1.0"), _pkg("bar", "2.0")]
    bom = _formatter().format(packages)

    root = next(d for d in bom["dependencies"] if d["ref"] == "os-component")
    assert root["dependsOn"] == ["pkg:pypi/foo@1.0", "pkg:pypi/bar@2.0"]


def test_product_excludes_itself_from_root_dependencies() -> None:
    """When the product is also one of the scanned packages (e.g. scanning a
    project's own venv), it must not be listed as a dependency of itself, and
    the root's dependsOn is the product's own *direct* dependencies, not
    every package in the environment."""
    packages = [
        _pkg("whatever2sbom", "0.1.dev1", deps=["pkg:pypi/mkdocs@1.6.1"]),
        _pkg("mkdocs", "1.6.1", deps=["pkg:pypi/mergedeep@1.3.4"]),
        _pkg("mergedeep", "1.3.4"),
    ]
    bom = _formatter(product_name="whatever2sbom", product_version="0.1.dev1").format(packages)

    root = next(d for d in bom["dependencies"] if d["ref"] == "product:whatever2sbom")
    # Only the direct dep -- mergedeep is transitive (via mkdocs) and must
    # not appear here.
    assert root["dependsOn"] == ["pkg:pypi/mkdocs@1.6.1"]

    # The package's own entry still carries its own declared dependencies.
    self_deps = next(
        d for d in bom["dependencies"] if d["ref"] == "pkg:pypi/whatever2sbom@0.1.dev1"
    )
    assert self_deps["dependsOn"] == ["pkg:pypi/mkdocs@1.6.1"]

    mkdocs_deps = next(d for d in bom["dependencies"] if d["ref"] == "pkg:pypi/mkdocs@1.6.1")
    assert mkdocs_deps["dependsOn"] == ["pkg:pypi/mergedeep@1.3.4"]

    compositions = bom["compositions"][0]["dependencies"]
    assert "pkg:pypi/whatever2sbom@0.1.dev1" not in compositions
    assert "pkg:pypi/mkdocs@1.6.1" in compositions
    assert "pkg:pypi/mergedeep@1.3.4" in compositions


def test_product_name_match_is_normalized() -> None:
    """Name comparison is PEP 503-ish: case/separator-insensitive."""
    packages = [_pkg("My_Cool.Tool", "1.0")]
    bom = _formatter(product_name="my-cool-tool", product_version="1.0").format(packages)

    root = next(d for d in bom["dependencies"] if d["ref"] == "product:my-cool-tool")
    assert root["dependsOn"] == []
