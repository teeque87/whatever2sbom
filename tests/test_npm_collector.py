"""Unit tests for the npm collector: lockfile discovery, integrity decoding,
license extraction, scope mapping, PURLs, and node_modules dependency
resolution."""

import base64
import hashlib
import json

import pytest

from whatever2sbom.collectors.npm import (
    NpmCollector,
    _candidate_node_modules,
    _extract_licenses,
    _filename_from_resolved,
    _find_lockfile,
    _hashes_from_integrity,
    _package_name_from_path,
    _resolve,
    _scope_for,
    _to_record,
)
from whatever2sbom.util import purl as _purl


# _package_name_from_path

@pytest.mark.parametrize("path, expected", [
    ("node_modules/lodash", "lodash"),
    ("node_modules/@scope/pkg", "@scope/pkg"),
    ("node_modules/a/node_modules/b", "b"),
    ("node_modules/@babel/core/node_modules/semver", "semver"),
])
def test_package_name_from_path(path: str, expected: str) -> None:
    assert _package_name_from_path(path) == expected


# npm PURL builder

def test_npm_purl_plain() -> None:
    assert _purl.npm("lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"


def test_npm_purl_scoped_encodes_at() -> None:
    assert _purl.npm("@angular/core", "12.3.1") == "pkg:npm/%40angular/core@12.3.1"


def test_npm_purl_encodes_plus_in_version() -> None:
    # "+" must be percent-encoded for OSV/PURL consumers.
    assert _purl.npm("foo", "1.0.0+build1") == "pkg:npm/foo@1.0.0%2Bbuild1"


# integrity decoding

def test_hashes_from_integrity_sha512_is_hex() -> None:
    digest = hashlib.sha512(b"payload").digest()
    integrity = "sha512-" + base64.b64encode(digest).decode()
    hashes = _hashes_from_integrity(integrity)
    assert hashes["sha512"] == digest.hex()
    assert len(hashes["sha512"]) == 128


def test_hashes_from_integrity_multiple_algorithms() -> None:
    sha1 = hashlib.sha1(b"x").digest()
    sha512 = hashlib.sha512(b"x").digest()
    integrity = f"sha1-{base64.b64encode(sha1).decode()} sha512-{base64.b64encode(sha512).decode()}"
    hashes = _hashes_from_integrity(integrity)
    assert hashes == {"sha1": sha1.hex(), "sha512": sha512.hex()}


def test_hashes_from_integrity_handles_missing_and_garbage() -> None:
    assert _hashes_from_integrity(None) == {}
    assert _hashes_from_integrity("sha512-") == {}
    assert _hashes_from_integrity("not-valid-base64!!!") == {}


# license extraction

@pytest.mark.parametrize("entry, expected", [
    ({"license": "MIT"}, ["MIT"]),
    ({"license": "(MIT OR Apache-2.0)"}, ["(MIT OR Apache-2.0)"]),
    ({"license": {"type": "ISC", "url": "https://..."}}, ["ISC"]),
    ({"license": [{"type": "MIT"}, {"type": "Apache-2.0"}]}, ["MIT", "Apache-2.0"]),
    ({"licenses": [{"type": "BSD-3-Clause"}]}, ["BSD-3-Clause"]),
    ({"license": "UNLICENSED"}, []),
    ({}, []),
])
def test_extract_licenses(entry: dict, expected: list[str]) -> None:
    assert _extract_licenses(entry) == expected


# scope mapping

@pytest.mark.parametrize("entry, expected", [
    ({}, "required"),
    ({"optional": True}, "optional"),
    ({"dev": True}, "excluded"),
    ({"devOptional": True}, "excluded"),
    ({"dev": True, "optional": True}, "excluded"),  # dev wins
])
def test_scope_for(entry: dict, expected: str) -> None:
    assert _scope_for(entry) == expected


# _to_record

def test_to_record_fills_core_fields() -> None:
    digest = hashlib.sha512(b"pkg").digest()
    entry = {
        "license": "MIT",
        "integrity": "sha512-" + base64.b64encode(digest).decode(),
        "resolved": "https://registry.npmjs.org/@scope/tool/-/tool-2.0.0.tgz",
        "bin": {"mytool": "cli.js"},
    }
    pkg = _to_record("@scope/tool", "2.0.0", entry)
    assert pkg.purl == "pkg:npm/%40scope/tool@2.0.0"
    assert pkg.bom_ref == pkg.purl
    assert pkg.component_type == "library"
    assert pkg.licenses == ["MIT"]
    assert pkg.sha512 == digest.hex()
    assert pkg.filename == "tool-2.0.0.tgz"
    assert pkg.bsi_executable == "executable"  # has a bin entry
    assert pkg.bsi_archive == "non-archive"
    assert pkg.bsi_structured == "structured"


def test_to_record_no_bin_is_non_executable() -> None:
    pkg = _to_record("lodash", "4.17.21", {"license": "MIT"})
    assert pkg.bsi_executable == "non-executable"


def test_to_record_surfaces_deprecated() -> None:
    pkg = _to_record("old-pkg", "1.0.0", {"deprecated": "use new-pkg instead"})
    assert ("npm:deprecated", "use new-pkg instead") in pkg.extra_properties


# filename from the resolved tarball URL

@pytest.mark.parametrize("resolved, expected", [
    ("https://registry.npmjs.org/@scope/tool/-/tool-2.0.0.tgz", "tool-2.0.0.tgz"),
    ("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "lodash-4.17.21.tgz"),
    ("https://example.com/pkg-1.0.0.tar.gz", "pkg-1.0.0.tar.gz"),
    # git / file / link resolveds have no artifact filename
    ("git+https://github.com/foo/bar.git#abc123", None),
    ("file:../local-pkg", None),
    (None, None),
    ("", None),
])
def test_filename_from_resolved(resolved, expected) -> None:
    assert _filename_from_resolved(resolved) == expected


# node_modules resolution walk

def test_candidate_node_modules_root() -> None:
    assert _candidate_node_modules("") == ["node_modules"]


def test_candidate_node_modules_top_level() -> None:
    assert _candidate_node_modules("node_modules/foo") == [
        "node_modules/foo/node_modules",
        "node_modules",
    ]


def test_candidate_node_modules_nested() -> None:
    assert _candidate_node_modules("node_modules/@babel/core/node_modules/semver") == [
        "node_modules/@babel/core/node_modules/semver/node_modules",
        "node_modules/@babel/core/node_modules",
        "node_modules",
    ]


def test_resolve_prefers_nearest_node_modules() -> None:
    packages = {
        "node_modules/semver": {},  # hoisted, top-level
        "node_modules/foo/node_modules/semver": {},  # foo's own nested copy
    }
    # foo resolves its own nested semver, not the hoisted one
    assert _resolve("node_modules/foo", "semver", packages) == "node_modules/foo/node_modules/semver"


def test_resolve_walks_up_to_root() -> None:
    packages = {"node_modules/semver": {}}
    assert _resolve("node_modules/foo", "semver", packages) == "node_modules/semver"


def test_resolve_unresolvable_returns_none() -> None:
    assert _resolve("node_modules/foo", "missing", {"node_modules/foo": {}}) is None


# end-to-end collect against a synthetic lockfile

def _write_lockfile(tmp_path, packages: dict, version: int = 3):
    data = {"name": "root", "lockfileVersion": version, "packages": packages}
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_collect_resolves_graph_and_dedups_dev(tmp_path) -> None:
    lock = _write_lockfile(tmp_path, {
        "": {"name": "root", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "license": "MIT", "dependencies": {"b": "^1.0.0"}},
        "node_modules/b": {"version": "1.0.0", "license": "ISC"},
        "node_modules/d": {"version": "1.0.0", "license": "MIT", "dev": True},
    })
    pkgs = NpmCollector(lockfile=str(lock)).collect()
    by_name = {p.name: p for p in pkgs}

    assert set(by_name) == {"a", "b", "d"}
    assert by_name["a"].dependency_refs == ["pkg:npm/b@1.0.0"]
    assert by_name["b"].dependency_refs == []
    assert by_name["d"].scope == "excluded"  # dev dependency


def test_collect_exclude_dev_drops_dev_packages_and_edges(tmp_path) -> None:
    lock = _write_lockfile(tmp_path, {
        "": {"name": "root"},
        "node_modules/a": {"version": "1.0.0", "license": "MIT", "dependencies": {"d": "^1.0.0"}},
        "node_modules/d": {"version": "1.0.0", "license": "MIT", "dev": True},
    })
    pkgs = NpmCollector(lockfile=str(lock), exclude_dev=True).collect()
    by_name = {p.name: p for p in pkgs}

    assert set(by_name) == {"a"}
    # the edge to the excluded dev package is dropped, not left dangling
    assert by_name["a"].dependency_refs == []


def test_collect_skips_link_and_versionless_entries(tmp_path) -> None:
    lock = _write_lockfile(tmp_path, {
        "": {"name": "root"},
        "node_modules/real": {"version": "1.0.0", "license": "MIT"},
        "node_modules/linked": {"link": True, "resolved": "packages/linked"},
        "node_modules/novers": {"license": "MIT"},
    })
    pkgs = NpmCollector(lockfile=str(lock)).collect()
    assert [p.name for p in pkgs] == ["real"]


def test_collect_rejects_unsupported_lockfile_version(tmp_path) -> None:
    lock = _write_lockfile(tmp_path, {}, version=1)
    with pytest.raises(RuntimeError, match="lockfileVersion"):
        NpmCollector(lockfile=str(lock)).collect()


# _find_lockfile

def test_find_lockfile_accepts_directory(tmp_path) -> None:
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    assert _find_lockfile(str(tmp_path)) == tmp_path / "package-lock.json"


def test_find_lockfile_falls_back_to_hidden_lockfile(tmp_path) -> None:
    """With no top-level package-lock.json, npm's node_modules/.package-lock.json
    is used as a fallback."""
    hidden = tmp_path / "node_modules" / ".package-lock.json"
    hidden.parent.mkdir()
    hidden.write_text("{}", encoding="utf-8")
    assert _find_lockfile(str(tmp_path)) == hidden


def test_find_lockfile_prefers_top_level_over_hidden(tmp_path) -> None:
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    hidden = tmp_path / "node_modules" / ".package-lock.json"
    hidden.parent.mkdir()
    hidden.write_text("{}", encoding="utf-8")
    assert _find_lockfile(str(tmp_path)) == tmp_path / "package-lock.json"


def test_find_lockfile_directory_without_any_lockfile(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="no npm lockfile under"):
        _find_lockfile(str(tmp_path))


def test_find_lockfile_explicit_file_missing(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="not found"):
        _find_lockfile(str(tmp_path / "nope.json"))
