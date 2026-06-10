import logging
import subprocess

from whatever2sbom.enrichers.base import Enricher
from whatever2sbom.models import PackageRecord

logger = logging.getLogger(__name__)

_APT_WANTED: dict[str, str] = {
    "package":             "package",
    "version":             "version",
    "sha256":              "sha256",
    "sha1":                "sha1",
    "sha512":              "sha512",
    "md5sum":              "md5sum",
    "size":                "size",
    "filename":            "filename",
    "original-maintainer": "original_maintainer",
}

_BATCH_SIZE = 100


def _parse_stanzas(raw: str) -> list[dict[str, str]]:
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in raw.splitlines():
        if line == "":
            if current:
                stanzas.append(current)
                current = {}
            continue
        if line[0] in (" ", "\t"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key_lower = key.strip().lower()
            if key_lower in _APT_WANTED:
                current[_APT_WANTED[key_lower]] = value.strip()

    if current:
        stanzas.append(current)
    return stanzas


def _fetch(names: list[str]) -> dict[tuple[str, str], dict[str, str]]:
    index: dict[tuple[str, str], dict[str, str]] = {}
    for i in range(0, len(names), _BATCH_SIZE):
        batch = names[i : i + _BATCH_SIZE]
        try:
            result = subprocess.run(
                ["apt-cache", "show", "--no-all-versions=false", *batch],
                capture_output=True, text=True, check=False,
            )
            for stanza in _parse_stanzas(result.stdout):
                name = stanza.get("package")
                version = stanza.get("version")
                if name and version:
                    index[(name, version)] = stanza
        except FileNotFoundError:
            logger.warning("  skipping apt-cache: command not found")
            break
    return index


class AptCacheEnricher(Enricher):
    """Enrich packages with hashes and filename from apt-cache show."""

    name = "apt-cache"

    def enrich(self, packages: list[PackageRecord]) -> list[PackageRecord]:
        logger.info("  fetching metadata for %d packages", len(packages))
        names = [p.name for p in packages]
        cache = _fetch(names)
        hits = 0

        for pkg in packages:
            apt = cache.get((pkg.name, pkg.version), {})
            if not apt:
                continue
            hits += 1
            for field in ("sha256", "sha1", "sha512", "md5sum", "size", "filename", "original_maintainer"):
                val = apt.get(field)
                if val:
                    setattr(pkg, field, val)

        logger.info("  ← %d / %d packages matched", hits, len(packages))
        return packages
