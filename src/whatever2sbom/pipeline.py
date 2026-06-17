import logging

from whatever2sbom.collectors.base import Collector
from whatever2sbom.enrichers.base import Enricher
from whatever2sbom.formatters.base import Formatter
from whatever2sbom.models import PackageRecord
from whatever2sbom.plugins.base import LoadedPlugin
from whatever2sbom.util import perf
from whatever2sbom.validators.base import ValidationError, Validator

logger = logging.getLogger(__name__)


class SbomPipeline:
    def __init__(
        self,
        collector: Collector,
        enrichers: list[Enricher],
        formatter: Formatter,
        validators: list[Validator],
        plugins: list[LoadedPlugin] | None = None,
    ) -> None:
        self.collector = collector
        self.enrichers = enrichers
        self.formatter = formatter
        self.validators = validators
        # Post-processing plugins run last, after formatting but *before*
        # validation, so whatever they emit is still checked against the schema.
        self.plugins = plugins or []

    def run(self) -> dict:
        logger.info("Collecting -> %s", self.collector.name)
        with perf.timed(f"collect:{self.collector.name}"):
            packages: list[PackageRecord] = self.collector.collect()

        for enricher in self.enrichers:
            logger.info("Enriching -> %s", enricher.name)
            with perf.timed(f"enrich:{enricher.name}"):
                packages = enricher.enrich(packages)

        logger.info("Formatting -> %s", self.formatter.name)
        with perf.timed(f"format:{self.formatter.name}"):
            bom = self.formatter.format(packages)

        for plugin in self.plugins:
            logger.info("Plugin -> %s", plugin.name)
            with perf.timed(f"plugin:{plugin.name}"):
                bom = plugin.run(bom)

        for validator in self.validators:
            logger.info("Validating -> %s", validator.name)
            with perf.timed(f"validate:{validator.name}"):
                errors = validator.validate(bom)
                if errors:
                    raise ValidationError(errors)

        return bom
