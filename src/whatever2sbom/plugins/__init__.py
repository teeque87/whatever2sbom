"""
Optional post-processing plugins.

A plugin is a single standalone Python script that gets the finished BOM (a
plain ``dict``) and returns a modified one. Plugins run as the *last* pipeline
stage before schema validation, so anything they emit is still validated
before it is written to disk.

See `loader.py` for how plugins are discovered and loaded, and
`builtin/patch-purl.py` for a worked example. The user-facing guide on writing
a plugin lives in `docs/plugins.md`.
"""

from whatever2sbom.plugins.base import LoadedPlugin, PluginError
from whatever2sbom.plugins.loader import (
    load_plugin,
    parse_plugin_configs,
    plugin_search_path,
)

__all__ = [
    "LoadedPlugin",
    "PluginError",
    "load_plugin",
    "parse_plugin_configs",
    "plugin_search_path",
]
