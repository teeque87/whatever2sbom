"""Tests for synthetic dpkg "source" pseudo-components: their construction in the
collector, exclusion from coverage stats, and relaxed BSI validation."""

from whatever2sbom.collectors.dpkg import _build_pseudo_sources
from whatever2sbom.formatters.cyclonedx16 import CycloneDXFormatter, coverage_stats
from whatever2sbom.models import SOURCE_PSEUDO_COMPONENT_PROPERTY, PackageRecord
from whatever2sbom.validators.bsi_tr03183 import BsiTr03183Validator


def _member(name: str, src: str | None, ver: str = "1.0-1", **kw) -> PackageRecord:
    return PackageRecord(name=name, version=ver, source_name=src, source_version=ver, **kw)


# _build_pseudo_sources

def test_pseudo_created_when_no_same_named_binary() -> None:
    members = [
        _member("libnvidia-cfg1-590", "nvidia-graphics-drivers-590",
                "590.48.01-0ubuntu0.24.04.5",
                maintainer="Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>",
                homepage="http://www.nvidia.com", scope="optional"),
        _member("nvidia-driver-590", "nvidia-graphics-drivers-590",
                "590.48.01-0ubuntu0.24.04.5", scope="required"),
    ]
    pseudo = _build_pseudo_sources(members, "ubuntu", "noble")

    assert len(pseudo) == 1
    p = pseudo[0]
    coord = "pkg:deb/ubuntu/nvidia-graphics-drivers-590@590.48.01-0ubuntu0.24.04.5?arch=source&distro=noble"
    assert p.name == "nvidia-graphics-drivers-590"
    assert p.version == "590.48.01-0ubuntu0.24.04.5"
    assert p.purl == coord
    assert p.bom_ref == coord
    # inherits shared packaging metadata
    assert p.maintainer == "Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>"
    assert p.homepage == "http://www.nvidia.com"
    assert p.description == "Source package for: libnvidia-cfg1-590, nvidia-driver-590"
    # required if any member is required
    assert p.scope == "required"
    assert (SOURCE_PSEUDO_COMPONENT_PROPERTY, "true") in p.extra_properties


def test_no_pseudo_when_same_named_binary_present() -> None:
    # source python3.12 ships a python3.12 binary -> that binary is the carrier.
    members = [
        _member("python3.12", "python3.12", "3.12.3-1"),
        _member("libpython3.12-stdlib", "python3.12", "3.12.3-1"),
    ]
    assert _build_pseudo_sources(members, "ubuntu", "noble") == []


def test_no_pseudo_for_own_source_package() -> None:
    # bash has no distinct source (source_name None -> falls back to "bash").
    members = [PackageRecord(name="bash", version="5.3-2ubuntu1")]
    assert _build_pseudo_sources(members, "ubuntu", "noble") == []


def test_pseudo_components_are_unique_and_disjoint_from_binaries() -> None:
    packages = [
        # group with no same-named binary -> pseudo "nvidia-graphics-drivers-590"
        _member("libnvidia-cfg1-590", "nvidia-graphics-drivers-590", "590.0-1"),
        _member("nvidia-driver-590", "nvidia-graphics-drivers-590", "590.0-1"),
        # another such group -> pseudo "linux-hwe-6.17"
        _member("linux-image-unsigned-6.17.0-14", "linux-hwe-6.17", "6.17.0-14.14"),
        # group WITH a same-named binary -> no pseudo
        _member("python3.12", "python3.12", "3.12.3-1"),
        _member("libpython3.12-stdlib", "python3.12", "3.12.3-1"),
    ]
    for p in packages:  # binary coordinate, as the collector assigns it
        p.bom_ref = f"pkg:deb/ubuntu/{p.name}@{p.version}?arch=amd64&distro=noble"

    pseudo = _build_pseudo_sources(packages, "ubuntu", "noble")
    pseudo_refs = [p.bom_ref for p in pseudo]

    assert sorted(p.name for p in pseudo) == ["linux-hwe-6.17", "nvidia-graphics-drivers-590"]
    assert len(pseudo_refs) == len(set(pseudo_refs))            # unique among themselves
    assert set(pseudo_refs).isdisjoint(p.bom_ref for p in packages)  # no collision with binaries


def test_pseudo_version_is_the_majority_source_version() -> None:
    # During a partial upgrade members may disagree; the majority wins.
    members = [
        _member("libnvidia-cfg1-590", "nvidia-graphics-drivers-590", "590.0-1"),
        _member("nvidia-driver-590", "nvidia-graphics-drivers-590", "590.0-1"),
        _member("nvidia-utils-590", "nvidia-graphics-drivers-590", "590.0-2"),
    ]
    pseudo = _build_pseudo_sources(members, "ubuntu", "noble")
    assert pseudo[0].version == "590.0-1"


# coverage stats (formatter)

def test_pseudo_excluded_from_coverage_percentages() -> None:
    real = PackageRecord(name="libfoo1", version="1.0", sha256="a" * 64, licenses=["MIT"])
    real.bom_ref = "pkg:deb/ubuntu/libfoo1@1.0?arch=amd64"
    real.purl = "pkg:deb/ubuntu/libfoo1@1.0?arch=source"
    pseudo = PackageRecord(
        name="foo", version="1.0",
        purl="pkg:deb/ubuntu/foo@1.0?arch=source",
        bom_ref="pkg:deb/ubuntu/foo@1.0?arch=source",
        extra_properties=[(SOURCE_PSEUDO_COMPONENT_PROPERTY, "true")],
    )
    bom = CycloneDXFormatter(product_supplier="Example Corp").format([real, pseudo])
    stats = coverage_stats(bom["components"])

    # total counts every component, but the pseudo-component is not counted as a
    # "missing" artifact in the coverage percentages.
    assert stats["total"] == 2
    assert stats["hash_coverage"] == 1
    assert stats["hash_coverage_pct"] == "100.0%"
    assert stats["license_coverage_pct"] == "100.0%"


# BSI validation (relaxed logical-component rules)

def test_pseudo_passes_bsi_as_logical_node() -> None:
    pseudo = PackageRecord(
        name="nvidia-graphics-drivers-590",
        version="590.48.01-0ubuntu0.24.04.5",
        maintainer="Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>",
        purl="pkg:deb/ubuntu/nvidia-graphics-drivers-590@590.48.01-0ubuntu0.24.04.5?arch=source&distro=noble",
        bom_ref="pkg:deb/ubuntu/nvidia-graphics-drivers-590@590.48.01-0ubuntu0.24.04.5?arch=source&distro=noble",
        extra_properties=[(SOURCE_PSEUDO_COMPONENT_PROPERTY, "true")],
    )
    fmt = CycloneDXFormatter(
        distro="ubuntu",
        product_name="Acme Gadget", product_version="1.0",
        product_supplier="Acme Corp", product_supplier_url=["https://acme.example"],
        product_purl="pkg:generic/acme/gadget@1.0",
        authors=["Jane Doe <jane@example.com>"],
    )
    bom = fmt.format([pseudo])
    # No filename / SHA-512 / licence errors for a logical source node.
    assert BsiTr03183Validator().validate(bom) == []
