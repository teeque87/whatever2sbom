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

_SPDX_SCHEMA = Path(__file__).parent / "schema" / "cdx" / "spdx.schema.json"

# "LicenseRef-<entity>-..." or "DocumentRef-<doc>:LicenseRef-<entity>-..."
# per "Annex B. SPDX license expressions".
_LICENSE_REF_RE = re.compile(r"^(DocumentRef-[\w.-]+:)?LicenseRef-[\w.-]+$")

_TOKEN_RE = re.compile(r"\(|\)|AND|OR|WITH|[^\s()]+")


@lru_cache(maxsize=1)
def license_ids() -> frozenset[str]:
    """All SPDX license + license-exception identifiers known to CycloneDX."""
    with open(_SPDX_SCHEMA, encoding="utf-8") as fh:
        data = json.load(fh)
    return frozenset(data["enum"])


def is_spdx_id(token: str) -> bool:
    """True if `token` (with optional trailing '+') is a known SPDX identifier."""
    base = token[:-1] if token.endswith("+") else token
    return base in license_ids()


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
            if not (is_spdx_id(tok) or is_license_ref(tok)):
                return False
            expect_operand = False

    return not expect_operand and depth == 0


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
    if is_license_ref(value):
        return {"kind": "name", "value": value, "compliant": True}
    if is_spdx_expression(value):
        return {"kind": "expression", "value": value, "compliant": True}
    return {"kind": "name", "value": value, "compliant": False}
