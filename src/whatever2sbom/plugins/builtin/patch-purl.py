"""
Built-in plugin: rewrite the PURL namespace of named components.

Some ecosystems put a namespace in the PURL (e.g. deb -> pkg:deb/debian/bash),
others don't (e.g. pypi -> pkg:pypi/requests). This plugin replaces that
namespace with one you define, for the packages you name -- handy when your
vulnerability tooling or internal catalogue keys on a different namespace
(e.g. pkg:deb/debian/bash -> pkg:deb/acme/bash).

It only touches PURLs that already *have* a namespace; a namespace-less PURL
(like pypi) is left unchanged.

Enable with:  --plugin patch-purl

Config keys (both required):
    namespace   the namespace to set.
    packages    list of component names to patch.

Example:
    --plugin patch-purl \
        --plugin-config patch-purl:namespace=acme \
        --plugin-config patch-purl:packages=bash,coreutils
"""

import logging

logger = logging.getLogger("whatever2sbom.plugin.patch-purl")


def _replace_namespace(purl: str, namespace: str) -> str:
    """Replace the namespace in `purl`, if it has one; otherwise return it as-is.

    A PURL is ``pkg:TYPE/NAMESPACE/NAME@VERSION?QUALIFIERS``. We split off the
    version/qualifiers, then look at the slash-separated coordinate: only when
    it has a namespace segment (TYPE / NAMESPACE / NAME) is it rewritten."""
    cut = min((purl.find(c) for c in "@?#" if c in purl), default=len(purl))
    coord, suffix = purl[:cut], purl[cut:]

    parts = coord.split("/")
    if len(parts) < 3:                 # no namespace (e.g. pkg:pypi/requests)
        return purl
    parts[1:-1] = [namespace]          # type / <namespace> / name
    return "/".join(parts) + suffix


def apply(bom: dict, config: dict) -> dict:
    namespace = config.get("namespace")
    packages = config.get("packages")
    if not namespace or not packages:
        raise ValueError(
            "patch-purl requires both 'namespace' and 'packages', e.g. "
            "--plugin-config patch-purl:namespace=acme "
            "--plugin-config patch-purl:packages=bash,coreutils"
        )

    targets = {packages} if isinstance(packages, str) else set(packages)
    patched = 0
    for component in bom.get("components", []):
        if component.get("name") in targets and component.get("purl"):
            new_purl = _replace_namespace(component["purl"], namespace)
            if new_purl != component["purl"]:
                component["purl"] = new_purl
                patched += 1

    logger.info("patch-purl: set namespace %r on %d component(s)", namespace, patched)
    return bom
