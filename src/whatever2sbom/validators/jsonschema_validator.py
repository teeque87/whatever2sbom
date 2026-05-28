import json
import logging
from pathlib import Path

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from whatever2sbom.validators.base import Validator

logger = logging.getLogger(__name__)

_DEFAULT_SCHEMA = (
    Path(__file__).parent.parent / "schema" / "cdx" / "bom-1.6.schema.json"
)


class CycloneDXSchemaValidator(Validator):
    """Validate a BOM dict against the bundled CycloneDX 1.6 JSON schema."""

    schema_name  = "cyclonedx"
    spec_version = "1.6"
    name         = f"{schema_name}-{spec_version}-jsonschema"

    def __init__(self, schema_path: Path | None = None) -> None:
        path = schema_path or _DEFAULT_SCHEMA
        with open(path, encoding="utf-8") as fh:
            schema = json.load(fh)

        # spdx.schema.json is referenced by the bom schema but not bundled.
        # Register a stub (open string type) so the rest of the schema validates
        # without a resolution error.
        registry = Registry().with_resources([
            (
                path.as_uri(),
                Resource.from_contents(schema, default_specification=DRAFT7),
            ),
            (
                (path.parent / "spdx.schema.json").as_uri(),
                Resource.from_contents({"type": "string"}, default_specification=DRAFT7),
            ),
        ])

        self._validator = jsonschema.Draft7Validator(schema, registry=registry)

    def validate(self, bom: dict) -> list[str]:
        errors: list[str] = []
        for error in self._validator.iter_errors(bom):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            errors.append(f"{path}: {error.message}")
        if errors:
            logger.warning("Schema validation: %d error(s)", len(errors))
        else:
            logger.info("Schema validation passed")
        return errors
