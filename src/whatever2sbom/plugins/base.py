"""
The plugin contract.

A plugin is a standalone ``.py`` file that defines a single top-level
function:

    def apply(bom: dict, config: dict) -> dict:
        ...
        return bom

`bom`     the finished BOM as a plain dict (the same structure the formatter
          produced). Mutate it in place and/or return a new dict.
`config`  this plugin's configuration (see loader.parse_plugin_configs):
          an empty dict when none was given.

The function MUST return the (modified) BOM dict. Raising any exception aborts
the run with a clear error -- raise ValueError with a helpful message for bad
or missing config.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


class PluginError(RuntimeError):
    """A plugin could not be loaded or failed while running."""


@dataclass
class LoadedPlugin:
    """A plugin script that has been located, imported, and bound to its config.

    The pipeline treats this like any other stage: it exposes `name` (for
    logging / perf timing) and `run(bom)`."""

    name: str
    path: Path
    apply: Callable[[dict, dict], dict]
    config: dict = field(default_factory=dict)

    def run(self, bom: dict) -> dict:
        logging.getLogger(__name__).debug(
            "running plugin %s (%s) with config %s", self.name, self.path, self.config
        )
        try:
            result = self.apply(bom, self.config)
        except Exception as exc:  # noqa: BLE001 -- surface any plugin failure uniformly
            raise PluginError(f"plugin {self.name!r} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise PluginError(
                f"plugin {self.name!r} must return the (modified) BOM dict, "
                f"got {type(result).__name__}"
            )
        return result
