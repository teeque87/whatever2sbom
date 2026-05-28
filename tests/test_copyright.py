"""Unit tests for DEP-5 copyright file parsing."""

from whatever2sbom.enrichers.copyright import _parse_dep5, _DEBIAN_TO_SPDX


_DEP5_SIMPLE = """\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: mylib

Files: *
Copyright: 2020 Someone
License: GPL-2+

Files: debian/*
Copyright: 2020 Packager
License: MIT
"""

_DEP5_NO_WILDCARD = """\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: src/*.c
Copyright: 2019 Author
License: Apache-2.0
"""


def test_parse_dep5_wildcard_first() -> None:
    result = _parse_dep5(_DEP5_SIMPLE)
    # Files: * should come first
    assert result[0] == "GPL-2+"
    assert "MIT" in result


def test_parse_dep5_no_wildcard() -> None:
    result = _parse_dep5(_DEP5_NO_WILDCARD)
    assert result == ["Apache-2.0"]


def test_parse_dep5_deduplication() -> None:
    content = """\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 A
License: MIT

Files: extra/*
Copyright: 2020 B
License: MIT
"""
    result = _parse_dep5(content)
    assert result.count("MIT") == 1


def test_debian_to_spdx_mapping() -> None:
    assert _DEBIAN_TO_SPDX["GPL-2+"] == "GPL-2.0-or-later"
    assert _DEBIAN_TO_SPDX["Apache-2"] == "Apache-2.0"
    assert _DEBIAN_TO_SPDX["MIT"] == "MIT"
