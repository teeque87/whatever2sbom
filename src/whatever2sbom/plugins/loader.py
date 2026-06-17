"""
Discover, load, and configure plugins.

Plugins are looked up by name (without the ``.py``) across an ordered search
path. The first matching ``<name>.py`` wins, so user-supplied directories take
precedence over the bundled built-ins -- a user can shadow a built-in by
dropping a file of the same name into one of their own plugin directories.

Search path (highest precedence first):
    1. $WHATEVER2SBOM_PLUGIN_PATH   (os.pathsep-separated list of directories)
    2. ./plugins                    (relative to the current working directory)
    3. ~/.whatever2sbom/plugins     (per-user drop-in directory)
    4. /opt/whatever2sbom/plugins   (system-wide drop-in, created by the .deb)
    5. the bundled built-in plugins shipped inside the package

Loading is by file path (importlib), so a plugin file may use any name --
including hyphens, e.g. ``patch-purl.py`` -> ``--plugin patch-purl``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path

from whatever2sbom.plugins.base import LoadedPlugin, PluginError

_ENV_VAR = "WHATEVER2SBOM_PLUGIN_PATH"
_BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"
_SYSTEM_DIR = Path("/opt/whatever2sbom/plugins")
_MODULE_NAME_RE = re.compile(r"[^0-9A-Za-z_]+")


def plugin_search_path() -> list[Path]:
    """Return the ordered, de-duplicated list of directories searched for plugins."""
    dirs: list[Path] = []

    env = os.environ.get(_ENV_VAR)
    if env:
        dirs += [Path(p) for p in env.split(os.pathsep) if p]

    dirs.append(Path.cwd() / "plugins")
    dirs.append(Path.home() / ".whatever2sbom" / "plugins")
    dirs.append(_SYSTEM_DIR)
    dirs.append(_BUILTIN_DIR)

    seen: set[str] = set()
    unique: list[Path] = []
    for d in dirs:
        resolved = d.expanduser()
        key = str(resolved)
        if key not in seen:
            seen.add(key)
            unique.append(resolved)
    return unique


def _find_plugin_file(name: str) -> Path:
    # A plugin name is a bare script name -- never a path. Reject anything that
    # could escape the search directories.
    if not name or name in (".", "..") or "/" in name or "\\" in name or os.sep in name:
        raise PluginError(f"invalid plugin name {name!r} (use a bare script name, e.g. patch-purl)")

    filename = name if name.endswith(".py") else f"{name}.py"
    search = plugin_search_path()
    for directory in search:
        candidate = directory / filename
        if candidate.is_file():
            return candidate

    searched = "\n  ".join(str(d) for d in search)
    raise PluginError(
        f"plugin {name!r} not found. Searched (in order):\n  {searched}"
    )


def _import_from_path(name: str, path: Path):
    # Use a unique, import-safe module name so two plugins (or a plugin and a
    # real package) never collide in sys.modules.
    mod_name = "whatever2sbom._plugin_" + _MODULE_NAME_RE.sub("_", name)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise PluginError(f"could not load plugin {name!r} from {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 -- report import-time errors clearly
        raise PluginError(f"plugin {name!r} ({path}) failed to import: {exc}") from exc
    return module


def load_plugin(name: str, config: dict | None = None) -> LoadedPlugin:
    """Locate, import, and bind the named plugin to its config.

    Raises PluginError if the plugin cannot be found, imported, or does not
    define a top-level ``apply(bom, config)`` callable."""
    path = _find_plugin_file(name)
    module = _import_from_path(name, path)
    apply = getattr(module, "apply", None)
    if not callable(apply):
        raise PluginError(
            f"plugin {name!r} ({path}) must define a top-level "
            f"apply(bom, config) function"
        )
    return LoadedPlugin(name=name, path=path, apply=apply, config=config or {})


def _coerce_value(raw: str):
    """Turn a CLI config value into a str or list[str].

    A value containing commas becomes a list (empty items dropped), so
    ``packages=foo,bar`` yields ``["foo", "bar"]``. Everything else stays a
    plain string."""
    if "," in raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


def parse_plugin_configs(
    inline: list[str] | None,
    config_file: str | None,
) -> dict[str, dict]:
    """Merge per-plugin config from a JSON file and inline ``NAME:KEY=VALUE`` flags.

    The JSON file (``{"plugin-name": {...}, ...}``) provides the base config;
    inline ``--plugin-config NAME:KEY=VALUE`` entries are layered on top and
    win on conflicts. Inline list values use comma separation
    (``NAME:packages=foo,bar``)."""
    configs: dict[str, dict] = {}

    if config_file:
        path = Path(config_file)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PluginError(f"could not read --plugin-config-file {config_file!r}: {exc}") from exc
        if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
            raise PluginError(
                f"--plugin-config-file {config_file!r} must be a JSON object mapping "
                f"plugin name -> config object"
            )
        for plugin_name, plugin_cfg in data.items():
            configs.setdefault(plugin_name, {}).update(plugin_cfg)

    for entry in inline or []:
        if ":" not in entry or "=" not in entry.split(":", 1)[1]:
            raise PluginError(
                f"invalid --plugin-config {entry!r}; expected NAME:KEY=VALUE "
                f"(e.g. patch-purl:namespace=acme)"
            )
        plugin_name, rest = entry.split(":", 1)
        key, value = rest.split("=", 1)
        configs.setdefault(plugin_name.strip(), {})[key.strip()] = _coerce_value(value)

    return configs
