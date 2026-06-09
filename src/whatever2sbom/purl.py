"""
PURL-spec-compliant percent-encoding and per-ecosystem PURL builders.

Each ecosystem has its own coordinate rules, so each gets its own builder
(deb today; pypi, npm, … slot in here as siblings later). Collectors call the
builder for their ecosystem and store the result on PackageRecord; formatters
stay ecosystem-blind and just emit the finished string.

The PURL spec keeps a small set of characters unencoded that Python's
urllib.parse.quote escapes (notably ":", "~"), and vice versa.
"""

from urllib.parse import quote as _urlquote


def quote_version(version: str) -> str:
    """Percent-encode a package version per the PURL spec.

    Keeps . - : ~ unencoded (safe per PURL spec examples). Notably, "+" is
    encoded — required by OSV.dev and other PURL consumers.
    """
    return _urlquote(version, safe=".-:~")


def deb(distro: str, name: str, version: str, arch: str, codename: str | None) -> str:
    """Build a Debian/Ubuntu package-url:

        pkg:deb/<distro>/<name>@<version>?arch=<arch>&distro=<codename>

    The arch and codename qualifiers are optional: an empty arch (or the dpkg
    meta-arch "all") omits the arch qualifier, and an empty codename omits
    distro. Pass arch="source" to produce the source coordinate that
    Debian/Ubuntu security data is keyed on.
    """
    out = f"pkg:deb/{distro}/{name}@{quote_version(version)}"
    qualifiers: list[str] = []
    if arch and arch != "all":
        qualifiers.append(f"arch={arch}")
    if codename:
        qualifiers.append(f"distro={codename}")
    if qualifiers:
        out += "?" + "&".join(qualifiers)
    return out
