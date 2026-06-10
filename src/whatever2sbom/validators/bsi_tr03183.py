"""
Optional, additional validator for BSI TR-03183-2 (v2.1.0) compliance.

This checks a formatted CycloneDX 1.6 BOM against the data-field
requirements of the BSI Technical Guideline ("Cyber Resilience Requirements
for Manufacturers and Products — Part 2: SBOM"), on top of the baseline
CycloneDX JSON-schema validation. It is opt-in via --bsi-tr-compliant,
since not every environment can supply all required data (e.g. component
creator e-mail/URL, SHA-512 hashes).
"""

import logging

from whatever2sbom import spdx
from whatever2sbom.validators.base import Validator

logger = logging.getLogger(__name__)

_REQUIRED_BSI_PROPERTIES = (
    "bsi:component:executable",
    "bsi:component:archive",
    "bsi:component:structured",
)


def _properties(node: dict) -> dict[str, str]:
    return {p["name"]: p.get("value", "") for p in node.get("properties", [])}


def _has_email_or_url(entity: dict | None) -> bool:
    """True if an organizationalEntity carries an e-mail address or URL."""
    if not entity:
        return False
    if entity.get("url"):
        return True
    return any(c.get("email") for c in entity.get("contact", []))


def _has_creator(node: dict) -> bool:
    """
    Component/SBOM creator per BSI TR-03183-2 §5.2.2 / §5.2.1: an e-mail
    address, falling back to a URL.
    """
    if _has_email_or_url(node.get("manufacturer")):
        return True
    if _has_email_or_url(node.get("supplier")):
        return True
    return any(a.get("email") for a in node.get("authors", []))


def _licenses_are_spdx_compliant(licenses: list[dict] | None) -> bool:
    """
    Distribution licences per BSI TR-03183-2 §6.1: SPDX license identifier(s)
    or expression(s), or LicenseRef-* identifiers.
    """
    if not licenses:
        return False

    if len(licenses) == 1 and "expression" in licenses[0]:
        return spdx.is_spdx_expression(licenses[0]["expression"])

    for entry in licenses:
        lic = entry.get("license", {})
        if "id" in lic:
            if not spdx.is_spdx_id(lic["id"]):
                return False
        elif "name" in lic:
            if not spdx.is_license_ref(lic["name"]):
                return False
        else:
            return False
    return True


def _has_sha512(hashes: list[dict] | None) -> bool:
    return any(h.get("alg") == "SHA-512" for h in (hashes or []))


class BsiTr03183Validator(Validator):
    """Check a CycloneDX 1.6 BOM against BSI TR-03183-2 v2.1.0 data-field requirements."""

    schema_name  = "cyclonedx"
    spec_version = "1.6"
    name         = "bsi-tr-03183-2"

    def validate(self, bom: dict) -> list[str]:
        errors: list[str] = []

        errors += self._check_format(bom)
        errors += self._check_sbom_fields(bom)

        component = bom.get("metadata", {}).get("component")
        if component:
            errors += self._check_logical_component(component, "metadata.component")

        for i, comp in enumerate(bom.get("components", [])):
            ref = comp.get("bom-ref") or comp.get("name", f"#{i}")
            errors += self._check_component(comp, f"components[{ref}]")

        if errors:
            logger.warning("BSI TR-03183-2 check failed: %d issue(s)", len(errors))
        else:
            logger.info("  ← BSI TR-03183-2 check passed")
        return errors

    # ── SBOM level (§5.2.1, §4) ──────────────────────────────────────────────

    def _check_format(self, bom: dict) -> list[str]:
        errors: list[str] = []
        if bom.get("bomFormat") != "CycloneDX":
            errors.append("bomFormat: MUST be CycloneDX or SPDX (BSI TR-03183-2 §4)")
        spec_version = bom.get("specVersion", "0")
        if tuple(int(p) for p in spec_version.split(".")) < (1, 6):
            errors.append(
                f"specVersion: {spec_version!r} — CycloneDX MUST be >= 1.6 (BSI TR-03183-2 §4)"
            )
        if bom.get("vulnerabilities"):
            errors.append(
                "vulnerabilities: MUST NOT be present in a BSI TR-03183-2 compliant SBOM (§3)"
            )
        return errors

    def _check_sbom_fields(self, bom: dict) -> list[str]:
        errors: list[str] = []
        metadata = bom.get("metadata", {})

        if not _has_creator(metadata):
            errors.append(
                "metadata: missing creator e-mail/URL "
                "(metadata.manufacturer or metadata.authors[].email) (BSI TR-03183-2 §5.2.1)"
            )
        if not metadata.get("timestamp"):
            errors.append("metadata.timestamp: MUST be present (BSI TR-03183-2 §5.2.1)")
        if not bom.get("serialNumber"):
            errors.append("serialNumber: SBOM-URI MUST be present (BSI TR-03183-2 §5.2.3)")

        return errors

    # ── component level (§5.2.2, §3.2.2) ─────────────────────────────────────

    def _check_logical_component(self, comp: dict, where: str) -> list[str]:
        """Logical component (e.g. metadata.component) — relaxed §3.2.2 field set."""
        errors: list[str] = []
        if not comp.get("name"):
            errors.append(f"{where}.name: MUST be present (BSI TR-03183-2 §3.2.2)")
        if not comp.get("version"):
            errors.append(f"{where}.version: MUST be present (BSI TR-03183-2 §3.2.2)")
        if not _has_creator(comp):
            errors.append(
                f"{where}: missing creator e-mail/URL "
                f"(supplier/manufacturer contact) (BSI TR-03183-2 §3.2.2)"
            )
        licenses = comp.get("licenses")
        if licenses is not None and not _licenses_are_spdx_compliant(licenses):
            errors.append(
                f"{where}.licenses: MUST use SPDX license identifiers/expressions "
                f"or LicenseRef-* (BSI TR-03183-2 §6.1)"
            )
        return errors

    def _check_component(self, comp: dict, where: str) -> list[str]:
        errors: list[str] = []

        if not comp.get("name"):
            errors.append(f"{where}.name: MUST be present (BSI TR-03183-2 §5.2.2)")
        if not comp.get("version"):
            errors.append(f"{where}.version: MUST be present (BSI TR-03183-2 §5.2.2)")
        if not _has_creator(comp):
            errors.append(
                f"{where}: missing creator e-mail/URL "
                f"(supplier/manufacturer contact) (BSI TR-03183-2 §5.2.2)"
            )

        props = _properties(comp)
        if not props.get("bsi:component:filename"):
            errors.append(
                f"{where}.properties: missing 'bsi:component:filename' (BSI TR-03183-2 §5.2.2)"
            )
        for prop_name in _REQUIRED_BSI_PROPERTIES:
            if prop_name not in props:
                errors.append(f"{where}.properties: missing '{prop_name}' (BSI TR-03183-2 §5.2.2)")

        if not _licenses_are_spdx_compliant(comp.get("licenses")):
            errors.append(
                f"{where}.licenses: MUST use SPDX license identifiers/expressions "
                f"or LicenseRef-* (BSI TR-03183-2 §6.1)"
            )

        if not _has_sha512(comp.get("hashes")):
            errors.append(
                f"{where}.hashes: missing SHA-512 of the deployable component "
                f"(BSI TR-03183-2 §5.2.2)"
            )

        return errors
