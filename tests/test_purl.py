"""Unit tests for PURL building and dpkg PURL assignment."""

import pytest

from whatever2sbom.util.purl import deb, pypi, quote_version
from whatever2sbom.collectors.dpkg import _fill_purls, _resolve_distro
from whatever2sbom.models import PackageRecord


# quote_version

@pytest.mark.parametrize("version, expected", [
    ("1.0",                  "1.0"),
    ("1.0-1ubuntu1",         "1.0-1ubuntu1"),
    ("1.0+dfsg-1",           "1.0%2Bdfsg-1"),
    ("2:1.02.205-2ubuntu3",  "2:1.02.205-2ubuntu3"),
    ("1.0~rc1",              "1.0~rc1"),
])
def test_quote_version(version: str, expected: str) -> None:
    assert quote_version(version) == expected


# deb() PURL builder

@pytest.mark.parametrize("distro,name,version,arch,codename,expected", [
    ("ubuntu", "poppler", "26.01.0-2build2", "source", "resolute",
     "pkg:deb/ubuntu/poppler@26.01.0-2build2?arch=source&distro=resolute"),
    ("ubuntu", "expat", "2.7.4+really-1", "source", "resolute",
     "pkg:deb/ubuntu/expat@2.7.4%2Breally-1?arch=source&distro=resolute"),
    ("ubuntu", "fonts-foo", "1.0-1", "all", "resolute",
     "pkg:deb/ubuntu/fonts-foo@1.0-1?distro=resolute"),
    ("ubuntu", "foo", "1.0-1", "", "resolute",
     "pkg:deb/ubuntu/foo@1.0-1?distro=resolute"),
    ("debian", "bar", "2.0", "amd64", None,
     "pkg:deb/debian/bar@2.0?arch=amd64"),
    ("debian", "baz", "3.0", "", None,
     "pkg:deb/debian/baz@3.0"),
])
def test_deb(distro, name, version, arch, codename, expected):
    assert deb(distro, name, version, arch, codename) == expected


# pypi() PURL builder

@pytest.mark.parametrize("name,version,expected", [
    ("flask",    "3.1.0",  "pkg:pypi/flask@3.1.0"),
    ("foo-bar",  "1.0+local", "pkg:pypi/foo-bar@1.0%2Blocal"),
])
def test_pypi(name, version, expected):
    assert pypi(name, version) == expected


# _resolve_distro

@pytest.mark.parametrize("override,os_info,want_distro,want_codename", [
    ("ubuntu", {"id": "debian", "version_codename": "bookworm"}, "ubuntu", "bookworm"),
    (None,     {"id": "ubuntu", "version_codename": "resolute"}, "ubuntu", "resolute"),
    (None,     {},                                                "debian", None),
])
def test_resolve_distro(override, os_info, want_distro, want_codename):
    distro, codename = _resolve_distro(override, os_info)
    assert distro == want_distro
    assert codename == want_codename


# _fill_purls

@pytest.mark.parametrize("pkg,want_purl,want_bom_ref", [
    (
        PackageRecord(name="poppler-utils", version="26.01.0-2build2", architecture="amd64",
                      source_name="poppler", source_version="26.01.0-2build2"),
        "pkg:deb/ubuntu/poppler@26.01.0-2build2?arch=source&distro=resolute",
        "pkg:deb/ubuntu/poppler-utils@26.01.0-2build2?arch=amd64&distro=resolute",
    ),
    (
        PackageRecord(name="libdevmapper1.02.1", version="2:1.02.205-2ubuntu3", architecture="amd64",
                      source_name="lvm2", source_version="2.03.31-2ubuntu3"),
        "pkg:deb/ubuntu/lvm2@2.03.31-2ubuntu3?arch=source&distro=resolute",
        "pkg:deb/ubuntu/libdevmapper1.02.1@2:1.02.205-2ubuntu3?arch=amd64&distro=resolute",
    ),
    (
        PackageRecord(name="bash", version="5.3-2ubuntu1", architecture="amd64"),
        "pkg:deb/ubuntu/bash@5.3-2ubuntu1?arch=source&distro=resolute",
        "pkg:deb/ubuntu/bash@5.3-2ubuntu1?arch=amd64&distro=resolute",
    ),
    (
        PackageRecord(name="fonts-foo", version="1.0-1", architecture="all",
                      source_name="foo", source_version="1.0-1"),
        "pkg:deb/ubuntu/foo@1.0-1?arch=source&distro=resolute",
        "pkg:deb/ubuntu/fonts-foo@1.0-1?distro=resolute",
    ),
])
def test_fill_purls(pkg, want_purl, want_bom_ref):
    _fill_purls(pkg, "ubuntu", "resolute")
    assert pkg.purl == want_purl, f"purl: got {pkg.purl!r}, want {want_purl!r}"
    assert pkg.bom_ref == want_bom_ref, f"bom_ref: got {pkg.bom_ref!r}, want {want_bom_ref!r}"
