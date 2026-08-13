"""
SPDX license identifier / expression helpers.

Backed by the bundled ``schema/cdx/spdx.schema.json`` enum (CycloneDX's
mirror of the official SPDX license + exception list) so classification
works fully offline.
"""

import json
import re
from functools import lru_cache
from pathlib import Path

_SPDX_SCHEMA = Path(__file__).parent.parent / "schema" / "cdx" / "spdx.schema.json"

# "LicenseRef-<entity>-..." or "DocumentRef-<doc>:LicenseRef-<entity>-..."
# per "Annex B. SPDX license expressions".
_LICENSE_REF_RE = re.compile(r"^(DocumentRef-[\w.-]+:)?LicenseRef-[\w.-]+$")

# A bare name usable as the "<entity>-..." part of "LicenseRef-<entity>-...".
_LICENSE_REF_NAME_RE = re.compile(r"^[\w.-]+$")

_TOKEN_RE = re.compile(r"\(|\)|AND|OR|WITH|[^\s()]+")

# Debian copyright files sometimes join SPDX ids with "_OR_" / "_AND_" /
# "_WITH_" instead of the SPDX expression syntax's spaced operators (e.g.
# "GPL-2.0-only_OR_LicenseRef-KDE-Accepted-GPL"). Normalizing these to spaced
# operators before validation recovers a proper SPDX expression; strings that
# aren't actually SPDX expressions (e.g. containing free-text "_with_parts_
# in_..._") simply fail validation afterwards and fall through unchanged.
_COMPOUND_OPERATOR_RE = re.compile(r"_(OR|AND|WITH)_")

# Common Debian DEP-5 "License:" short names that are just an alternate name
# for an SPDX-listed license (case-insensitive lookup -> canonical SPDX id).
_SPDX_ALIASES: dict[str, str] = {
    # "Expat" is the name the MIT license's original authors (the X Consortium /
    # MIT's X11 distribution via Expat) used, and SPDX's "MIT" id is that same text.
    "expat": "MIT",
    "mit/x11": "MIT",
    "mit/x": "MIT",
    # Boost Software License 1.0 -- Debian's short name vs. SPDX's id.
    "boost-1.0": "BSL-1.0",
    # Creative Commons CC0 -- Debian often drops the "-1.0" suffix.
    "cc0": "CC0-1.0",
    # The "zlib/libpng License" *is* the Zlib license; SPDX's id is "Zlib".
    "zlib": "Zlib",
    "zlib/libpng": "Zlib",
    # PSF's "Python License" short name vs. SPDX's versioned id.
    "python": "Python-2.0",
    # SIL Open Font License 1.1 -- several Debian short names in use.
    "sil-1.1": "OFL-1.1",
    "sil-ofl-1.1": "OFL-1.1",
    "ofl-v1.1": "OFL-1.1",
    # Bitstream Vera fonts license.
    "bitstream": "Bitstream-Vera",
    "bitstream-vera": "Bitstream-Vera",
    "bitstreamvera": "Bitstream-Vera",
}


@lru_cache(maxsize=1)
def license_ids() -> frozenset[str]:
    """All SPDX license + license-exception identifiers known to CycloneDX."""
    with open(_SPDX_SCHEMA, encoding="utf-8") as fh:
        data = json.load(fh)
    return frozenset(data["enum"])


def is_spdx_id(token: str) -> bool:
    """True if `token` is exactly a known SPDX license/exception identifier."""
    return token in license_ids()


def is_spdx_id_with_later(token: str) -> bool:
    """
    True if `token` is `<id>+`, the legacy SPDX "or later version" suffix,
    where `<id>` (without the trailing '+') is a known SPDX identifier.

    This is valid SPDX *expression* syntax even when `token` itself is not a
    literal entry in the SPDX license list (e.g. "GFDL-1.2+").
    """
    return token.endswith("+") and token[:-1] in license_ids()


def is_license_ref(token: str) -> bool:
    """True if `token` is a well-formed LicenseRef-* identifier."""
    return bool(_LICENSE_REF_RE.match(token))


def is_spdx_expression(expr: str) -> bool:
    """
    Best-effort validation of an SPDX license expression: identifiers (with
    optional '+' or LicenseRef-*) combined with AND / OR / WITH and
    parentheses, per the SPDX license expression syntax.
    """
    expr = expr.strip()
    if not expr:
        return False

    tokens = _TOKEN_RE.findall(expr)
    if not tokens:
        return False

    expect_operand = True
    depth = 0
    for tok in tokens:
        if tok == "(":
            if not expect_operand:
                return False
            depth += 1
        elif tok == ")":
            if expect_operand or depth == 0:
                return False
            depth -= 1
        elif tok in ("AND", "OR", "WITH"):
            if expect_operand:
                return False
            expect_operand = True
        else:
            if not expect_operand:
                return False
            if not (is_spdx_id(tok) or is_spdx_id_with_later(tok) or is_license_ref(tok)):
                return False
            expect_operand = False

    return not expect_operand and depth == 0


# A valid SPDX identifier/expression is a single short line. Anything with a
# newline, or far longer than the longest real-world expression, is license
# *text* that leaked into an identifier field (e.g. a package that pasted its
# whole LICENSE into the metadata `License` field) -- never a valid entry.
_MAX_LICENSE_ID_LEN = 200


def is_probably_license_text(value: str) -> bool:
    """True if `value` looks like license *text*, not a license *identifier*."""
    return "\n" in value or len(value) > _MAX_LICENSE_ID_LEN


def classify_license(raw: str) -> dict:
    """
    Classify a license string for CycloneDX output / BSI TR-03183-2 compliance.

    Returns a dict with:
      - kind: "id" (single SPDX identifier), "expression" (SPDX license
        expression with operators), or "name" (LicenseRef-* or unmapped text)
      - value: the (stripped) string to use
      - compliant: whether this satisfies the BSI TR-03183-2 requirement to
        use an SPDX license identifier/expression or a LicenseRef-* identifier
    """
    value = raw.strip()
    if is_spdx_id(value):
        return {"kind": "id", "value": value, "compliant": True}
    alias = _SPDX_ALIASES.get(value.lower())
    if alias:
        return {"kind": "id", "value": alias, "compliant": True}
    if is_license_ref(value):
        return {"kind": "name", "value": value, "compliant": True}
    if is_spdx_expression(value):
        return {"kind": "expression", "value": value, "compliant": True}
    normalized = _COMPOUND_OPERATOR_RE.sub(r" \1 ", value)
    if normalized != value and is_spdx_expression(normalized):
        return {"kind": "expression", "value": normalized, "compliant": True}
    # A Debian DEP-5 "License:" short name with no SPDX equivalent is itself an
    # identifier defined within that package's own copyright file (the full
    # text follows in the same "License:" stanza, carried in the component's
    # `copyright` field) -- exactly what LicenseRef-* exists for (BSI
    # TR-03183-2 §6.1 accepts SPDX ids/expressions *or* LicenseRef-*).
    if _LICENSE_REF_NAME_RE.match(value):
        return {"kind": "name", "value": f"LicenseRef-{value}", "compliant": True}
    return {"kind": "name", "value": value, "compliant": False}
