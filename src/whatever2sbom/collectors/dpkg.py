import logging
import subprocess

from whatever2sbom.collectors.base import Collector
from whatever2sbom.models import PackageRecord

logger = logging.getLogger(__name__)

# Fields fetched from dpkg-query.
# status_want / status_status are used only for filtering; they are not stored
# on PackageRecord.  sha1 / sha512 are not available here — they come from the
# AptCacheEnricher.
_FIELDS: dict[str, str] = {
    "package":        "${binary:Package}",
    "version":        "${Version}",
    "architecture":   "${Architecture}",
    "source":         "${Source}",
    "section":        "${Section}",
    "priority":       "${Priority}",
    "installed_size": "${Installed-Size}",
    "maintainer":     "${Maintainer}",
    "homepage":       "${Homepage}",
    "origin":         "${Origin}",
    "bugs":           "${Bugs}",
    "essential":      "${Essential}",
    "multi_arch":     "${Multi-Arch}",
    "depends":        "${Depends}",
    "pre_depends":    "${Pre-Depends}",
    "provides":       "${Provides}",
    "description":    "${Description}",
    "filename":       "${Filename}",
    "size":           "${Size}",
    "md5sum":         "${MD5sum}",
    "sha256":         "${SHA256}",
    # installation status — used for filtering only
    "status_want":    "${db:Status-Want}",
    "status_status":  "${db:Status-Status}",
}

_RECORD_SEP = "---RECORD_END---"


def _build_format_string() -> str:
    parts = "\n".join(f"{key}={var}" for key, var in _FIELDS.items())
    return parts + f"\n{_RECORD_SEP}\n"


def _parse_record(block: str) -> dict[str, str]:
    record: dict[str, str] = {}
    current_key: str | None = None
    current_lines: list[str] = []

    def _flush() -> None:
        if current_key is not None:
            record[current_key] = "\n".join(current_lines).strip()

    for line in block.splitlines():
        matched = next((k for k in _FIELDS if line.startswith(f"{k}=")), None)
        if matched:
            _flush()
            current_key = matched
            current_lines = [line[len(matched) + 1:]]
        elif current_key is not None:
            current_lines.append(line)

    _flush()
    return record


def _to_record(raw: dict[str, str]) -> PackageRecord:
    def v(key: str) -> str | None:
        val = raw.get(key, "")
        return val if val else None

    return PackageRecord(
        name=raw["package"],
        version=v("version") or "",
        architecture=v("architecture"),
        source=v("source"),
        section=v("section"),
        priority=v("priority"),
        installed_size=v("installed_size"),
        maintainer=v("maintainer"),
        homepage=v("homepage"),
        origin=v("origin"),
        bugs=v("bugs"),
        essential=v("essential"),
        multi_arch=v("multi_arch"),
        depends=v("depends"),
        pre_depends=v("pre_depends"),
        provides=v("provides"),
        description=v("description"),
        filename=v("filename"),
        size=v("size"),
        md5sum=v("md5sum"),
        sha256=v("sha256"),
    )


class DpkgCollector(Collector):
    """Collect installed packages via dpkg-query."""

    name = "dpkg"

    def __init__(self, installed_only: bool = True) -> None:
        self._installed_only = installed_only

    def collect(self) -> list[PackageRecord]:
        fmt = _build_format_string()
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", f"--showformat={fmt}"],
                capture_output=True, text=True, check=True,
            )
        except FileNotFoundError:
            raise RuntimeError("dpkg-query not found — is this a Debian/Ubuntu system?")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"dpkg-query failed: {e.stderr.strip()}") from e

        packages: list[PackageRecord] = []
        for block in result.stdout.split(_RECORD_SEP):
            block = block.strip()
            if not block:
                continue
            raw = _parse_record(block)
            if not raw.get("package"):
                continue
            if self._installed_only:
                if raw.get("status_want") != "install" or raw.get("status_status") != "installed":
                    continue
            packages.append(_to_record(raw))

        logger.info("Collected %d packages via dpkg-query", len(packages))
        return packages
