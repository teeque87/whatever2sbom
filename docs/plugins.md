# Plugins

A plugin is a small, optional Python script that gets the finished SBOM and hands back a modified
one. Plugins run as the **last** pipeline stage — after the formatter has built the document, but
*before* schema validation — so whatever a plugin changes is still validated before it is written
to disk.

Plugins are entirely opt-in: without `--plugin`, nothing changes.

```
whatever2sbom --product-supplier acme --plugin patch-purl \
    --plugin-config patch-purl:namespace=acme \
    --plugin-config patch-purl:packages=bash,coreutils
```

## Where plugins live

Enable a plugin with `--plugin <name>`, where `<name>` is the script's filename **without** the
`.py`. The file is looked up across these directories, **highest precedence first**:

1. `$WHATEVER2SBOM_PLUGIN_PATH` — an `os.pathsep`-separated list of directories (handy for
   development: `WHATEVER2SBOM_PLUGIN_PATH=./my-plugins`).
2. `./plugins` — relative to the current working directory.
3. `~/.whatever2sbom/plugins` — your personal drop-in directory.
4. `/opt/whatever2sbom/plugins` — the system-wide drop-in directory (created by the `.deb`).
5. The plugins bundled inside whatever2sbom (e.g. [`patch-purl`](#built-in-patch-purl)).

The first matching `<name>.py` wins, so you can shadow a built-in by dropping a file of the same
name into a higher-precedence directory. To install a plugin system-wide, just copy the `.py` into
`/opt/whatever2sbom/plugins`:

```
sudo cp my-plugin.py /opt/whatever2sbom/plugins/
whatever2sbom --product-supplier acme --plugin my-plugin
```

You can enable several plugins at once; they run left to right:

```
whatever2sbom --product-supplier acme --plugin patch-purl --plugin tag-internal
```

## Writing a plugin

A plugin is one `.py` file with a single top-level `apply` function:

```python
# my-plugin.py
def apply(bom: dict, config: dict) -> dict:
    """Receive the finished BOM dict, return the modified one."""
    for component in bom.get("components", []):
        component.setdefault("properties", []).append(
            {"name": "acme:reviewed", "value": "true"}
        )
    return bom
```

That's the whole contract:

- **`bom`** is the finished BOM as a plain `dict` — the exact structure the formatter produced
  (for CycloneDX: `components`, `dependencies`, `metadata`, …). See [Output format](output.md) for
  what's in it.
- **`config`** is this plugin's configuration (see [below](#configuring-a-plugin)); it's an empty
  dict when none was given.
- You **must return the (modified) BOM dict.** You can mutate `bom` in place and `return bom`, or
  build and return a new dict.

A few rules of thumb:

- **Stay offline.** Like the rest of whatever2sbom, plugins must not make network calls at runtime
  — bundle any reference data alongside the script.
- **Fail loudly.** Raise `ValueError` (or any exception) with a helpful message for bad or missing
  config; the run aborts with `Plugin error: …` and a non-zero exit code, before anything is
  written.
- **Mind the schema.** Your output is validated immediately after, so don't remove required fields
  or write malformed PURLs — a broken document fails the run instead of being written.
- **Log, don't print.** Use the standard `logging` module
  (`logging.getLogger("whatever2sbom.plugin.my-plugin")`); messages appear on stderr and respect
  `-v`.

### Configuring a plugin

Plugins read everything they need from the `config` dict, so the same script can behave differently
per run. There are two ways to populate it, and they compose:

**Inline**, with repeatable `--plugin-config NAME:KEY=VALUE` flags. A comma-separated value becomes
a list:

```
--plugin-config my-plugin:namespace=acme \
--plugin-config my-plugin:packages=requests,urllib3
```

gives `my-plugin` the config `{"namespace": "acme", "packages": ["requests", "urllib3"]}`.

**From a file**, with `--plugin-config-file FILE` — a JSON object mapping plugin name to its config
object:

```json
{
  "my-plugin": {
    "namespace": "acme",
    "packages": ["requests", "urllib3"]
  }
}
```

When both are given, the file provides the base config and inline `--plugin-config` values are
layered on top (inline wins on conflicts). Reach for the file when the config is large or you want
it under version control; reach for inline flags for quick one-offs.

Read config defensively so the plugin still works when a key is absent:

```python
def apply(bom: dict, config: dict) -> dict:
    namespace = config.get("namespace")
    if namespace is None:
        raise ValueError("my-plugin: 'namespace' is required")
    packages = config.get("packages") or []   # always a list
    ...
    return bom
```

## Built-in: `patch-purl`

whatever2sbom ships one plugin as a reference and a genuinely useful tool: `patch-purl` rewrites the
**namespace** of named components' PURLs. This is handy when your vulnerability tooling or internal
catalogue keys on a different namespace — for example turning `pkg:deb/debian/bash` into
`pkg:deb/acme/bash`.

It only touches PURLs that already *have* a namespace. Some ecosystems include one
(deb → `pkg:deb/debian/bash`), others don't (pypi → `pkg:pypi/requests`); a namespace-less PURL is
left unchanged.

| Config key | Required | Meaning |
|---|---|---|
| `namespace` | yes | The namespace to set. |
| `packages` | yes | List of component names to patch. There is no "patch everything" mode — naming the packages is deliberate. Matching is loose: a name matches if it equals an entry exactly, or begins with it followed by `-`, so `linux-hwe` also patches the versioned binary packages `linux-hwe-4828.2.1.1`, `linux-hwe-tools`, etc. |

```
whatever2sbom --product-supplier acme \
    --plugin patch-purl \
    --plugin-config patch-purl:namespace=acme \
    --plugin-config patch-purl:packages=bash,coreutils
```

Its source (`src/whatever2sbom/plugins/builtin/patch-purl.py`) is a complete, commented example to
copy from when writing your own.

## Built-in: `promote-upstream`

For `dpkg`, the matchable PURL uses the source coordinate (`arch=source`) **only** for packages
that are their own source; a binary built from a differently-named source instead carries its own
binary coordinate plus an informational `upstream=<source>` qualifier, which OSV/Dependency-Track
do **not** match on (see [Output format](output.md#source-coordinate-matching)). That's a
deliberate best-effort trade-off to avoid per-binary duplicate findings — but it means those
packages aren't scanned for source-level CVEs.

`promote-upstream` lets you opt specific packages back into source matching. For each named
component whose PURL has an `upstream=<source>` qualifier, it rewrites the PURL to the source
coordinate: the name segment becomes the upstream source, `arch` becomes `source`, and the
`upstream` qualifier is dropped. The component's `name` and `bom-ref` are left untouched — only the
matchable PURL changes.

The motivating case is a custom/HWE kernel, whose image binary is built from a source like
`linux-hwe-6.17` that advisories are published against:

```
pkg:deb/ubuntu/linux-image-unsigned-6.17.0-14-customos@6.17.0-14.14-0?arch=amd64&distro=noble&upstream=linux-hwe-6.17
→ pkg:deb/ubuntu/linux-hwe-6.17@6.17.0-14.14-0?arch=source&distro=noble
```

| Config key | Required | Meaning |
|---|---|---|
| `packages` | yes | List of component names to promote. Matching is loose (same rule as `patch-purl`): a name matches if it equals an entry exactly, or begins with it followed by `-`, so `linux-image-unsigned` catches `linux-image-unsigned-6.17.0-14-customos`. |

```
whatever2sbom --product-supplier acme \
    --plugin promote-upstream \
    --plugin-config promote-upstream:packages=linux-image-unsigned
```

A matched component with no `upstream=` qualifier (e.g. one that is already its own source) is left
unchanged. **Caveat:** if several matched binaries share the same upstream source, they're all
rewritten to the *same* source coordinate, re-introducing the per-binary duplication this tool
otherwise avoids — so name the packages precisely (usually just the kernel image package).
