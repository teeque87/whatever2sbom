import logging

from whatever2sbom.collectors.base import Collector
from whatever2sbom.enrichers.base import Enricher
from whatever2sbom.formatters.base import Formatter
from whatever2sbom.models import PackageRecord
from whatever2sbom.validators.base import ValidationError, Validator

logger = logging.getLogger(__name__)


class SbomPipeline:
    def __init__(
        self,
        collector: Collector,
        enrichers: list[Enricher],
        formatter: Formatter,
        validators: list[Validator],
    ) -> None:
        self.collector = collector
        self.enrichers = enrichers
        self.formatter = formatter
        self.validators = validators

    def run(self) -> dict:
        logger.info("Collecting via %s", self.collector.name)
        packages: list[PackageRecord] = self.collector.collect()
        logger.info("Collected %d packages", len(packages))

        for enricher in self.enrichers:
            logger.info("Enriching via %s", enricher.name)
            packages = enricher.enrich(packages)

        logger.info("Formatting via %s", self.formatter.name)
        bom = self.formatter.format(packages)

        for validator in self.validators:
            logger.info("Validating via %s", validator.name)
            errors = validator.validate(bom)
            if errors:
                raise ValidationError(errors)

        return bom
