"""
Built-in plugin: promote a deb component's `upstream=<source>` qualifier to the
matchable source coordinate.

whatever2sbom emits the source coordinate (arch=source) only for packages that
are their own source; a binary built from a differently-named source carries its
own binary coordinate plus an informational `upstream=<source>` qualifier, which
OSV/Dependency-Track do NOT match on (see docs/output.md). That's a deliberate
best-effort trade-off, but it means such packages aren't scanned for source-level
CVEs.

This plugin lets you opt specific packages back into source matching. For each
named component whose PURL has an `upstream=<source>` qualifier, it rewrites the
PURL to the source coordinate the security trackers key on:

    pkg:deb/ubuntu/linux-image-unsigned-6.17.0-14-customos@6.17.0-14.14-0
        ?arch=amd64&distro=noble&upstream=linux-hwe-6.17
 ->
    pkg:deb/ubuntu/linux-hwe-6.17@6.17.0-14.14-0?arch=source&distro=noble

i.e. the name segment becomes the upstream source, arch becomes `source`, and
the `upstream` qualifier is dropped; other qualifiers (distro, version) are kept.
The component's name and bom-ref are left untouched — only the matchable PURL
changes. This is exactly what's needed for custom/HWE kernels, whose image
binary (`linux-image-unsigned-…`) is built from a source like `linux-hwe-6.17`
that advisories are published against.

Enable with:  --plugin promote-upstream

Config key (required):
    packages    list of component names to promote. Matching is loose: a name
                matches if it equals an entry exactly, or begins with it followed
                by "-" -- so "linux-image-unsigned" catches the versioned binary
                "linux-image-unsigned-6.17.0-14-customos".

Example:
    --plugin promote-upstream \
        --plugin-config promote-upstream:packages=linux-image-unsigned

Caveat: if several matched binaries share the same upstream source, they will all
be rewritten to the *same* source coordinate, which re-introduces the per-binary
duplication this tool otherwise avoids. Name the packages precisely (usually just
the kernel image package).
"""

import logging

logger = logging.getLogger("whatever2sbom.plugin.promote-upstream")


def _matches(name: str, targets: set[str]) -> bool:
    """A name matches if it equals a target or begins with `target + "-"`,
    so a base name like "linux-image-unsigned" also catches its versioned
    binary packages without matching unrelated names."""
    return any(name == t or name.startswith(t + "-") for t in targets)


def _promote(purl: str) -> str | None:
    """Rewrite a deb PURL's `upstream=<source>` into the source coordinate.

    Returns the rewritten PURL, or None when there is nothing to promote (the
    PURL has no qualifiers, or no `upstream=` qualifier)."""
    base, sep, query = purl.partition("?")
    if not sep:
        return None

    upstream: str | None = None
    rest: list[str] = []
    for qualifier in query.split("&"):
        if not qualifier:
            continue
        key, _, value = qualifier.partition("=")
        if key == "upstream":
            upstream = value
        elif key == "arch":
            continue  # replaced by arch=source below
        else:
            rest.append(qualifier)

    if not upstream:
        return None

    # base is pkg:TYPE/NAMESPACE/NAME@VERSION; replace the NAME segment (the last
    # path component before the version) with the upstream source name.
    coord, at, version = base.partition("@")
    parts = coord.split("/")
    parts[-1] = upstream
    new_base = "/".join(parts) + at + version
    new_query = "&".join(["arch=source", *rest])
    return f"{new_base}?{new_query}"


def apply(bom: dict, config: dict) -> dict:
    packages = config.get("packages")
    if not packages:
        raise ValueError(
            "promote-upstream requires 'packages', e.g. "
            "--plugin-config promote-upstream:packages=linux-image-unsigned"
        )

    targets = {packages} if isinstance(packages, str) else set(packages)
    promoted = 0
    for component in bom.get("components", []):
        name = component.get("name")
        purl = component.get("purl")
        if not (name and purl and _matches(name, targets)):
            continue
        new_purl = _promote(purl)
        if new_purl is None:
            logger.warning(
                "promote-upstream: %r has no upstream= qualifier to promote; left unchanged",
                name,
            )
            continue
        if new_purl != purl:
            component["purl"] = new_purl
            promoted += 1
            logger.debug("promote-upstream: %s -> %s", purl, new_purl)

    logger.info(
        "promote-upstream: rewrote %d component PURL(s) to the source coordinate", promoted
    )
    return bom
