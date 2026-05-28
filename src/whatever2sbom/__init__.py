from importlib.metadata import PackageNotFoundError, metadata as _meta

_PACKAGE = "whatever2sbom"

try:
    _m = _meta(_PACKAGE)
    __version__ = _m["Version"]
    __title__   = _m["Name"]
except PackageNotFoundError:
    __version__ = "0.0.0+dev"
    __title__   = _PACKAGE
