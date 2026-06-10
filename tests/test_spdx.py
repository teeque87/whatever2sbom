"""Unit tests for SPDX license identifier / expression classification."""

import pytest

from whatever2sbom.spdx import (
    classify_license,
    is_license_ref,
    is_spdx_expression,
    is_spdx_id,
    is_spdx_id_with_later,
)


@pytest.mark.parametrize("token, expected", [
    ("MIT", True),
    ("Apache-2.0", True),
    ("GPL-2.0-or-later", True),
    ("GPL-2.0+", True),
    ("Classpath-exception-2.0", True),
    ("GPL-2.0-only+", False),
    ("Not-A-License", False),
    ("LicenseRef-Acme-Foo", False),
])
def test_is_spdx_id(token: str, expected: bool) -> None:
    assert is_spdx_id(token) is expected


@pytest.mark.parametrize("token, expected", [
    ("GPL-2.0-only+", True),
    ("GFDL-1.2+", True),
    ("MPL-1.1+", True),
    ("Not-A-License+", False),
    ("MIT", False),
])
def test_is_spdx_id_with_later(token: str, expected: bool) -> None:
    assert is_spdx_id_with_later(token) is expected


@pytest.mark.parametrize("token, expected", [
    ("LicenseRef-Acme-Foo", True),
    ("LicenseRef-scancode-proprietary-license", True),
    ("DocumentRef-foo:LicenseRef-bar", True),
    ("MIT", False),
    ("LicenseRef", False),
])
def test_is_license_ref(token: str, expected: bool) -> None:
    assert is_license_ref(token) is expected


@pytest.mark.parametrize("expr, expected", [
    ("MIT", True),
    ("MIT OR Apache-2.0", True),
    ("(MIT OR Apache-2.0) AND BSD-3-Clause", True),
    ("GPL-2.0-or-later WITH Classpath-exception-2.0", True),
    ("LicenseRef-Acme-Foo OR MIT", True),
    ("", False),
    ("MIT OR", False),
    ("MIT AND (Apache-2.0", False),
    ("Some made up text", False),
    ("MIT Apache-2.0", False),
])
def test_is_spdx_expression(expr: str, expected: bool) -> None:
    assert is_spdx_expression(expr) is expected


def test_classify_license_id() -> None:
    result = classify_license(" MIT ")
    assert result == {"kind": "id", "value": "MIT", "compliant": True}


def test_classify_license_expression() -> None:
    result = classify_license("MIT OR Apache-2.0")
    assert result == {"kind": "expression", "value": "MIT OR Apache-2.0", "compliant": True}


def test_classify_license_ref() -> None:
    result = classify_license("LicenseRef-Acme-Foo")
    assert result == {"kind": "name", "value": "LicenseRef-Acme-Foo", "compliant": True}


def test_classify_license_unmapped() -> None:
    result = classify_license("Some made up text")
    assert result == {"kind": "name", "value": "Some made up text", "compliant": False}


def test_classify_license_dep5_public_domain() -> None:
    """Common DEP-5 short names without an SPDX id map to LicenseRef-*."""
    result = classify_license("public-domain")
    assert result == {"kind": "name", "value": "LicenseRef-public-domain", "compliant": True}


def test_classify_license_expat_alias_for_mit() -> None:
    """"Expat" is Debian's name for the MIT license text."""
    result = classify_license("Expat")
    assert result == {"kind": "id", "value": "MIT", "compliant": True}


def test_classify_license_legacy_or_later() -> None:
    """"<id>+" forms not in the literal SPDX enum are valid SPDX expressions."""
    result = classify_license("GFDL-1.2+")
    assert result == {"kind": "expression", "value": "GFDL-1.2+", "compliant": True}


@pytest.mark.parametrize("alias, expected_id", [
    ("MIT/X11", "MIT"),
    ("Boost-1.0", "BSL-1.0"),
    ("CC0", "CC0-1.0"),
    ("zlib", "Zlib"),
    ("zlib/libpng", "Zlib"),
    ("Python", "Python-2.0"),
    ("SIL-1.1", "OFL-1.1"),
    ("Bitstream", "Bitstream-Vera"),
])
def test_classify_license_known_aliases(alias: str, expected_id: str) -> None:
    result = classify_license(alias)
    assert result == {"kind": "id", "value": expected_id, "compliant": True}


def test_classify_license_compound_underscore_expression() -> None:
    """Debian sometimes joins ids with "_OR_"/"_WITH_" instead of spaces."""
    result = classify_license("GPL-2.0-only_OR_GPL-3.0-only_OR_LicenseRef-KDE-Accepted-GPL")
    assert result == {
        "kind": "expression",
        "value": "GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL",
        "compliant": True,
    }


def test_classify_license_unmappable_compound_falls_back_to_license_ref() -> None:
    # "_OR_" normalizes but the result still isn't a valid SPDX expression
    # (free text), so it falls back to a generic LicenseRef-* of the raw name.
    result = classify_license("GPL_OR_BSD_with_parts_under_MIT")
    assert result == {
        "kind": "name",
        "value": "LicenseRef-GPL_OR_BSD_with_parts_under_MIT",
        "compliant": True,
    }


def test_classify_license_arbitrary_dep5_name_becomes_license_ref() -> None:
    result = classify_license("permissive-fsf-grant-attribution")
    assert result == {
        "kind": "name",
        "value": "LicenseRef-permissive-fsf-grant-attribution",
        "compliant": True,
    }
