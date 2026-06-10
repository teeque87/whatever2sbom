import json
import logging
from pathlib import Path

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from whatever2sbom.validators.base import Validator

logger = logging.getLogger(__name__)

_SCHEMA_DIR = Path(__file__).parent.parent / "schema" / "cdx"


class CycloneDXSchemaValidator(Validator):
    """
    Validate a BOM dict against a bundled CycloneDX JSON schema.

    The schema file is derived from `spec_version`
    (`schema/cdx/bom-<spec_version>.schema.json`), so adding support for a new
    CycloneDX release is just:
        1. Drop the new bom-<version>.schema.json (and updated
           spdx.schema.json, if needed) into schema/cdx/.
        2. Subclass with `spec_version = "<version>"` and register it.
    """

    schema_name  = "cyclonedx"
    spec_version = "1.6"

    @property
    def name(self) -> str:
        return f"{self.schema_name}-{self.spec_version}-jsonschema"

    def __init__(self, schema_path: Path | None = None) -> None:
        path = schema_path or _SCHEMA_DIR / f"bom-{self.spec_version}.schema.json"
        spdx_path = path.parent / "spdx.schema.json"

        with open(path, encoding="utf-8") as fh:
            schema = json.load(fh)
        with open(spdx_path, encoding="utf-8") as fh:
            spdx_schema = json.load(fh)

        registry = Registry().with_resources([
            (
                path.as_uri(),
                Resource.from_contents(schema, default_specification=DRAFT7),
            ),
            (
                spdx_path.as_uri(),
                Resource.from_contents(spdx_schema, default_specification=DRAFT7),
            ),
        ])
        # Pre-crawl so $ref resolution doesn't re-scan the whole schema on
        # every lookup (otherwise each of the ~150k $refs in a large BOM
        # triggers a fresh crawl of the entire document).
        registry = registry.crawl()

        self._validator = jsonschema.Draft7Validator(schema, registry=registry)

    def validate(self, bom: dict) -> list[str]:
        errors: list[str] = []
        for error in self._validator.iter_errors(bom):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            errors.append(f"{path}: {error.message}")
        if errors:
            logger.warning("Schema validation failed: %d error(s)", len(errors))
        else:
            logger.info("  <- Validation passed")
        return errors
