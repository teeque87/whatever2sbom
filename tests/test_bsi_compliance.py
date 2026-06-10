"""Tests for BSI TR-03183-2 license/property emission and validation."""

from whatever2sbom.formatters.cyclonedx16 import CycloneDXFormatter
from whatever2sbom.models import PackageRecord
from whatever2sbom.validators.bsi_tr03183 import BsiTr03183Validator


def _format(packages: list[PackageRecord]) -> dict:
    fmt = CycloneDXFormatter(
        distro="ubuntu",
        product_name="Acme Gadget",
        product_version="1.0",
        product_supplier="Acme Corp",
        product_supplier_url=["https://acme.example"],
        product_purl="pkg:generic/acme/gadget@1.0",
        authors=["Jane Doe <jane@example.com>"],
    )
    return fmt.format(packages)


def _compliant_package(**overrides) -> PackageRecord:
    defaults = dict(
        name="libfoo1",
        version="1.2.3-1",
        architecture="amd64",
        maintainer="Jane Doe <jane@example.com>",
        licenses=["MIT"],
        sha512="a" * 128,
        filename="pool/main/f/foo/libfoo1_1.2.3-1_amd64.deb",
        bom_ref="pkg:deb/ubuntu/libfoo1@1.2.3-1?arch=amd64",
        purl="pkg:deb/ubuntu/libfoo1@1.2.3-1?arch=source",
    )
    defaults.update(overrides)
    return PackageRecord(**defaults)


# ── license emission ────────────────────────────────────────────────────────

def test_single_spdx_id_emitted_as_license_id() -> None:
    bom = _format([_compliant_package(licenses=["MIT"])])
    assert bom["components"][0]["licenses"] == [
        {"license": {
            "id": "MIT",
            "url": "https://spdx.org/licenses/MIT.html",
            "acknowledgement": "declared",
        }}
    ]


def test_single_spdx_expression_emitted_as_expression() -> None:
    bom = _format([_compliant_package(
        licenses=["GPL-2.0-or-later WITH Classpath-exception-2.0"]
    )])
    assert bom["components"][0]["licenses"] == [
        {"expression": "GPL-2.0-or-later WITH Classpath-exception-2.0", "acknowledgement": "declared"}
    ]


def test_unmapped_license_falls_back_to_name() -> None:
    bom = _format([_compliant_package(licenses=["Some made up text"])])
    assert bom["components"][0]["licenses"] == [
        {"license": {"name": "Some made up text", "acknowledgement": "declared"}}
    ]


def test_no_licenses_omits_field() -> None:
    bom = _format([_compliant_package(licenses=[])])
    assert "licenses" not in bom["components"][0]


# ── BSI properties / compositions ───────────────────────────────────────────

def test_copyright_emitted_when_present() -> None:
    bom = _format([_compliant_package(copyright="2020 Jane Doe")])
    assert bom["components"][0]["copyright"] == "2020 Jane Doe"


def test_copyright_omitted_when_absent() -> None:
    bom = _format([_compliant_package()])
    assert "copyright" not in bom["components"][0]


def test_authors_built_from_maintainer() -> None:
    bom = _format([_compliant_package(maintainer="Jane Doe <jane@example.com>")])
    assert bom["components"][0]["authors"] == [{"name": "Jane Doe", "email": "jane@example.com"}]


def test_authors_prefer_original_maintainer_over_maintainer() -> None:
    bom = _format([_compliant_package(
        maintainer="Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
        original_maintainer="John Upstream <john@example.com>",
    )])
    assert bom["components"][0]["authors"] == [{"name": "John Upstream", "email": "john@example.com"}]
    # supplier still reflects who actually built/distributed the package
    assert bom["components"][0]["supplier"]["name"] == "Ubuntu Developers"


def test_bsi_properties_present() -> None:
    bom = _format([_compliant_package()])
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["bsi:component:filename"] == "libfoo1_1.2.3-1_amd64.deb"
    assert props["bsi:component:executable"] == "non-executable"
    assert props["bsi:component:archive"] == "archive"
    assert props["bsi:component:structured"] == "structured"
    assert props["bsi:component:effectiveLicense"] == "MIT"


def test_effective_license_combines_multiple_spdx_licenses() -> None:
    bom = _format([_compliant_package(licenses=["MIT", "Apache-2.0"])])
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["bsi:component:effectiveLicense"] == "(MIT) AND (Apache-2.0)"


def test_effective_license_omitted_for_non_spdx_license() -> None:
    bom = _format([_compliant_package(licenses=["Some made up text"])])
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert "bsi:component:effectiveLicense" not in props


def test_compositions_marks_dependency_completeness() -> None:
    bom = _format([_compliant_package()])
    assert bom["compositions"] == [{
        "aggregate": "unknown",
        "dependencies": ["pkg:generic/acme/gadget@1.0", "pkg:deb/ubuntu/libfoo1@1.2.3-1?arch=amd64"],
    }]


# ── BsiTr03183Validator ──────────────────────────────────────────────────────

def test_fully_compliant_component_passes() -> None:
    bom = _format([_compliant_package()])
    assert BsiTr03183Validator().validate(bom) == []


def test_missing_hash_and_creator_are_flagged() -> None:
    bom = _format([_compliant_package(maintainer=None, sha512=None)])
    errors = BsiTr03183Validator().validate(bom)
    assert any("creator e-mail/URL" in e for e in errors)
    assert any("SHA-512" in e for e in errors)


def test_non_spdx_license_is_flagged() -> None:
    bom = _format([_compliant_package(licenses=["Some made up text"])])
    errors = BsiTr03183Validator().validate(bom)
    assert any("SPDX license identifiers" in e for e in errors)


def test_vulnerabilities_present_is_flagged() -> None:
    bom = _format([_compliant_package()])
    bom["vulnerabilities"] = [{"id": "CVE-2024-0000"}]
    errors = BsiTr03183Validator().validate(bom)
    assert any("vulnerabilities" in e for e in errors)
