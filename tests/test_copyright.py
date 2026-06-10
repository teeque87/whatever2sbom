"""Unit tests for DEP-5 copyright file parsing."""

from whatever2sbom.enrichers.copyright import _extract_fsf_licenses, _is_dep5, _parse_dep5, _DEBIAN_TO_SPDX


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
    licenses, notice = _parse_dep5(_DEP5_SIMPLE)
    # Files: * should come first
    assert licenses[0] == "GPL-2+"
    assert "MIT" in licenses
    assert notice == "2020 Someone"


def test_parse_dep5_no_wildcard() -> None:
    licenses, notice = _parse_dep5(_DEP5_NO_WILDCARD)
    assert licenses == ["Apache-2.0"]
    assert notice == "2019 Author"


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
    licenses, notice = _parse_dep5(content)
    assert licenses.count("MIT") == 1
    assert notice == "2020 A"


def test_parse_dep5_multiline_copyright() -> None:
    content = """\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: Copyright © 2000-2008 Silicon Graphics, Inc.
 Copyright © 1999-2001,2007-2009 Andreas Gruenbacher
License: MIT
"""
    _, notice = _parse_dep5(content)
    assert notice == (
        "Copyright © 2000-2008 Silicon Graphics, Inc.\n"
        "Copyright © 1999-2001,2007-2009 Andreas Gruenbacher"
    )


def test_debian_to_spdx_mapping() -> None:
    assert _DEBIAN_TO_SPDX["GPL-2+"] == "GPL-2.0-or-later"
    assert _DEBIAN_TO_SPDX["Apache-2"] == "Apache-2.0"
    assert _DEBIAN_TO_SPDX["MIT"] == "MIT"


def test_is_dep5_current_format_url() -> None:
    assert _is_dep5("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n")


def test_is_dep5_legacy_format_specification_field() -> None:
    # Older DEP-5 drafts used "Format-Specification:" with a svn.debian.org URL.
    assert _is_dep5("Format-Specification: http://svn.debian.org/wsvn/dep/web/deps/dep5.mdwn?rev=59\n")


def test_is_dep5_false_for_freeform_copyright() -> None:
    assert not _is_dep5("This package was debianized by Someone <someone@example.com>.\n")


_BINUTILS_FREEFORM = """\
This is the Debian GNU/Linux prepackaged version of the GNU assembler,
linker, and binary utilities.

binutils is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

binutils is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU
General Public License along with this program; if not, write to
the Free Software Foundation. On Debian systems, the complete text of the
GNU General Public License can be found in `/usr/share/common-licenses/GPL'
and `/usr/share/common-licenses/LGPL'.

Some manuals are licensed under the terms of the GNU
Free Documentation License Version 1.3 or any later version published
by the Free Software Foundation; the complete text of the license can be found
in `/usr/share/common-licenses/GFDL'.
"""


def test_extract_fsf_licenses_gpl_and_gfdl() -> None:
    assert _extract_fsf_licenses(_BINUTILS_FREEFORM) == [
        "GPL-3.0-or-later",
        "GFDL-1.3-or-later",
    ]


def test_extract_fsf_licenses_gpl_only_without_or_later() -> None:
    content = (
        "Licensed under the GNU General Public License, version 2 of the License."
    )
    assert _extract_fsf_licenses(content) == ["GPL-2.0-only"]


def test_extract_fsf_licenses_lgpl_library_alias() -> None:
    content = (
        "under the terms of the GNU Library General Public License "
        "version 2 as published by the Free Software Foundation"
    )
    assert _extract_fsf_licenses(content) == ["LGPL-2.0-only"]


def test_extract_fsf_licenses_no_match_for_unrelated_text() -> None:
    assert _extract_fsf_licenses("This package was debianized by Someone.\n") == []


_BUP_FREEFORM = """\
License:

    GNU LGPL version 2
    See "/usr/share/common-licenses/LGPL-2".

The Debian packaging is:

    Copyright © 2010-2012 Jon Dowland <jmtd@debian.org>

and is similarly licensed under the LGPL version 2,
see "/usr/share/common-licenses/LGPL-2".
"""


def test_extract_fsf_licenses_bare_lgpl_abbreviation() -> None:
    assert _extract_fsf_licenses(_BUP_FREEFORM) == ["LGPL-2.0-only"]


def test_parse_dep5_legacy_format_specification() -> None:
    content = """\
Format-Specification: http://svn.debian.org/wsvn/dep/web/deps/dep5.mdwn?rev=59
Source: https://launchpad.net/aptdaemon

Files: *
Copyright: © 2008-2009 Sebastian Heinlein <devel@glatzor.de>
License: GPL-2+
"""
    assert _is_dep5(content)
    licenses, notice = _parse_dep5(content)
    assert licenses == ["GPL-2+"]
    assert notice == "© 2008-2009 Sebastian Heinlein <devel@glatzor.de>"
