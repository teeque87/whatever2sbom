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


def test_group_emitted_before_name_when_set() -> None:
    pkg = _pkg("libpython3.12-stdlib", "3.12.3-1")
    pkg.group = "python3.12"
    comp = _formatter().format([pkg])["components"][0]

    assert comp["group"] == "python3.12"
    keys = list(comp.keys())
    assert keys.index("group") < keys.index("name")  # group precedes name


def test_group_omitted_when_unset() -> None:
    comp = _formatter().format([_pkg("bash", "5.3")])["components"][0]
    assert "group" not in comp


def test_product_author_sets_component_authors() -> None:
    """--product-author records who authored the product itself
    (metadata.component.authors), distinct from the SBOM's own authors."""
    bom = _formatter(
        product_name="app",
        product_version="1.0",
        product_author=["Jane Doe <jane@example.com>", "Ops Team"],
    ).format([])

    assert bom["metadata"]["component"]["authors"] == [
        {"name": "Jane Doe", "email": "jane@example.com"},
        {"name": "Ops Team"},
    ]
    # SBOM-level authors (metadata.authors) stay separate and unset here.
    assert "authors" not in bom["metadata"]


def test_product_author_absent_omits_component_authors() -> None:
    bom = _formatter(product_name="app", product_version="1.0").format([])
    assert "authors" not in bom["metadata"]["component"]


def test_supplier_is_manufacturer_at_metadata_level_not_duplicated() -> None:
    """The product supplier is the component's supplier and the BOM's
    manufacturer (two distinct CycloneDX roles) -- not a redundant top-level
    metadata.supplier that just repeats metadata.component.supplier."""
    bom = CycloneDXFormatter(
        product_name="app",
        product_version="1.0",
        product_supplier="Example Corp",
        product_supplier_url=["https://example.com"],
        product_supplier_email="ops@example.com",
    ).format([])

    expected = {
        "name": "Example Corp",
        "url": ["https://example.com"],
        "contact": [{"email": "ops@example.com"}],
    }
    assert bom["metadata"]["manufacturer"] == expected
    assert bom["metadata"]["component"]["supplier"] == expected
    assert "supplier" not in bom["metadata"]


def test_no_product_name_and_describe_os_false_omits_metadata_component() -> None:
    """e.g. --system pip without --product-name: the scanned thing isn't the
    host OS, so metadata.component must not be a misleading
    operating-system fallback -- it's omitted entirely."""
    packages = [_pkg("foo", "1.0"), _pkg("bar", "2.0")]
    bom = _formatter(describe_os=False).format(packages)

    assert "component" not in bom["metadata"]
    assert not any(d["ref"] is None for d in bom["dependencies"])
    refs = {pkg.bom_ref for pkg in packages}
    assert {d["ref"] for d in bom["dependencies"]} == refs
    assert set(bom["compositions"][0]["dependencies"]) == refs
