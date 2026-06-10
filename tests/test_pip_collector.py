"""Unit tests for the pip collector: venv discovery, name normalisation,
PURL assignment, and Requires-Dist dependency resolution."""

from email.message import Message
from types import SimpleNamespace

import pytest

from whatever2sbom.collectors.pip import (
    _dep_applies,
    _find_venv,
    _fill_purls,
    _license,
    _normalize,
    _project_url,
    _resolve_dependencies,
    _to_record,
)
from whatever2sbom.models import PackageRecord
from packaging.requirements import Requirement


# ── _normalize (PEP 503) ────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw, expected", [
    ("Flask",        "flask"),
    ("PyYAML",       "pyyaml"),
    ("Foo_Bar.Baz",  "foo-bar-baz"),
    ("foo--bar",     "foo-bar"),
    ("zope.interface", "zope-interface"),
])
def test_normalize(raw: str, expected: str) -> None:
    assert _normalize(raw) == expected


# ── _fill_purls ──────────────────────────────────────────────────────────────────

def test_fill_purls() -> None:
    pkg = PackageRecord(name="Flask_Foo", version="1.0")
    _fill_purls(pkg)
    assert pkg.purl == "pkg:pypi/flask-foo@1.0"
    assert pkg.bom_ref == "pkg:pypi/flask-foo@1.0"


# ── _find_venv ───────────────────────────────────────────────────────────────────

def test_find_venv_explicit(tmp_path) -> None:
    venv = tmp_path / "myenv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("")
    assert _find_venv(str(venv), str(tmp_path)) == venv


def test_find_venv_explicit_missing_cfg(tmp_path) -> None:
    venv = tmp_path / "not-a-venv"
    venv.mkdir()
    with pytest.raises(RuntimeError, match="pyvenv.cfg"):
        _find_venv(str(venv), str(tmp_path))


def test_find_venv_explicit_ignores_virtual_env_var(tmp_path, monkeypatch) -> None:
    """$VIRTUAL_ENV must never override an explicit --venv-dir."""
    venv = tmp_path / "myenv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("")
    other = tmp_path / "tool-venv"
    other.mkdir()
    (other / "pyvenv.cfg").write_text("")
    monkeypatch.setenv("VIRTUAL_ENV", str(other))
    assert _find_venv(str(venv), str(tmp_path)) == venv


def test_find_venv_project_dir_is_venv(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    (tmp_path / "pyvenv.cfg").write_text("")
    assert _find_venv(None, str(tmp_path)) == tmp_path


def test_find_venv_auto_discovers_arbitrary_name(tmp_path, monkeypatch) -> None:
    """A venv directory with any name is found via its pyvenv.cfg marker."""
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    venv = tmp_path / "whatever-i-named-it"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("")
    assert _find_venv(None, str(tmp_path)) == venv


def test_find_venv_multiple_candidates(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    for name in ("env-a", "env-b"):
        d = tmp_path / name
        d.mkdir()
        (d / "pyvenv.cfg").write_text("")
    with pytest.raises(RuntimeError, match="Multiple virtualenvs"):
        _find_venv(None, str(tmp_path))


def test_find_venv_none_found(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    with pytest.raises(RuntimeError, match="No virtualenv found"):
        _find_venv(None, str(tmp_path))


def test_find_venv_ignores_virtual_env_var_when_no_local_venv(tmp_path, monkeypatch) -> None:
    """A venv active via $VIRTUAL_ENV (e.g. whatever2sbom's own) must not be
    picked up for the *target* project when --venv-dir/--project-dir don't
    point at it."""
    other = tmp_path / "tool-venv"
    other.mkdir()
    (other / "pyvenv.cfg").write_text("")
    monkeypatch.setenv("VIRTUAL_ENV", str(other))

    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(RuntimeError, match="No virtualenv found"):
        _find_venv(None, str(project))


# ── dependency resolution ─────────────────────────────────────────────────────────

class _FakeDistribution:
    """Minimal stand-in for importlib.metadata.Distribution."""

    def __init__(self, name, version, requires=None, extras=None, console_scripts=False, files=None):
        meta = Message()
        meta["Name"] = name
        meta["Version"] = version
        for extra in extras or []:
            meta["Provides-Extra"] = extra
        self.metadata = meta
        self.requires = requires or []
        self.entry_points = (
            [SimpleNamespace(group="console_scripts")] if console_scripts else []
        )
        self._files = files or {}

    def read_text(self, filename):
        return self._files.get(filename)


_ENV = {"python_version": "3.99", "sys_platform": "neverland"}


def test_dep_applies_no_marker() -> None:
    req = Requirement("requests")
    assert _dep_applies(req, _ENV) is True


def test_dep_applies_marker_matches_environment() -> None:
    req = Requirement('requests; python_version == "3.99"')
    assert _dep_applies(req, _ENV) is True


def test_dep_applies_marker_does_not_match() -> None:
    req = Requirement('requests; python_version == "2.7"')
    assert _dep_applies(req, _ENV) is False


def test_dep_applies_extra_marker_excluded() -> None:
    """Deps gated on `extra == "..."` are excluded -- including a package's
    own dev/test extras (e.g. pluggy[testing] requiring pytest), which would
    otherwise create false edges and dependency cycles."""
    req = Requirement('pytest; extra == "testing"')
    assert _dep_applies(req, _ENV) is False


def test_resolve_dependencies_basic() -> None:
    foo = PackageRecord(name="foo", version="1.0", bom_ref="pkg:pypi/foo@1.0")
    bar = PackageRecord(name="Bar", version="2.0", bom_ref="pkg:pypi/bar@2.0")
    packages = [foo, bar]
    dists = [
        _FakeDistribution("foo", "1.0", requires=["bar>=1.0"]),
        _FakeDistribution("Bar", "2.0", requires=[]),
    ]

    _resolve_dependencies(packages, dists, _ENV)

    assert foo.dependency_refs == ["pkg:pypi/bar@2.0"]
    assert bar.dependency_refs == []


def test_resolve_dependencies_skips_unmatched_marker() -> None:
    foo = PackageRecord(name="foo", version="1.0", bom_ref="pkg:pypi/foo@1.0")
    bar = PackageRecord(name="bar", version="2.0", bom_ref="pkg:pypi/bar@2.0")
    packages = [foo, bar]
    dists = [
        _FakeDistribution("foo", "1.0", requires=['bar; python_version == "2.7"']),
        _FakeDistribution("bar", "2.0", requires=[]),
    ]

    _resolve_dependencies(packages, dists, _ENV)

    assert foo.dependency_refs == []


# ── license resolution ───────────────────────────────────────────────────────────

def _meta(**headers: str) -> Message:
    meta = Message()
    meta["Name"] = "foo"
    meta["Version"] = "1.0"
    for key, value in headers.items():
        meta[key.replace("_", "-")] = value
    return meta


def _dist_for(meta: Message, files: dict[str, str] | None = None) -> _FakeDistribution:
    dist = _FakeDistribution(meta["Name"], meta["Version"], files=files)
    dist.metadata = meta
    return dist


def test_license_prefers_license_expression() -> None:
    meta = _meta(**{"License-Expression": "MIT", "License": "Some free text"})
    assert _license(meta, _dist_for(meta)) == "MIT"


def test_license_falls_back_to_license_field() -> None:
    meta = _meta(License="Apache-2.0")
    assert _license(meta, _dist_for(meta)) == "Apache-2.0"


def test_license_ignores_unknown_license_field() -> None:
    meta = _meta(License="UNKNOWN")
    meta["Classifier"] = "License :: OSI Approved :: MIT License"
    assert _license(meta, _dist_for(meta)) == "MIT"


def test_license_from_classifier() -> None:
    meta = _meta()
    meta["Classifier"] = "License :: OSI Approved :: Apache Software License"
    assert _license(meta, _dist_for(meta)) == "Apache-2.0"


def test_license_ambiguous_classifier_not_mapped() -> None:
    """"BSD License" covers multiple SPDX variants, so it's left unresolved
    unless a bundled License-File can be classified instead."""
    meta = _meta()
    meta["Classifier"] = "License :: OSI Approved :: BSD License"
    assert _license(meta, _dist_for(meta)) is None


def test_to_record_sets_license_from_expression() -> None:
    dist = _FakeDistribution("attrs", "26.1.0")
    dist.metadata["License-Expression"] = "MIT"
    pkg = _to_record(dist)
    assert pkg.licenses == ["MIT"]


# ── license recognition from a bundled License-File ──────────────────────────────

_MIT_TEXT = (
    "MIT License\n\nCopyright (c) 2026 someone\n\n"
    "Permission is hereby granted, free of charge, ..."
)
_APACHE_TEXT = (
    "                                 Apache License\n"
    "                           Version 2.0, January 2004\n"
    "                        http://www.apache.org/licenses/\n"
)
_BSD3_TEXT = (
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions are met:\n"
    "...\n"
    "3. Neither the name of the copyright holder nor the names of its\n"
    "   contributors may be used to endorse or promote products derived\n"
    "   from this software without specific prior written permission.\n"
)
_BSD2_TEXT = (
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions are met:\n"
    "1. Redistributions of source code must retain the above copyright notice.\n"
    "2. Redistributions in binary form must reproduce the above copyright notice.\n"
)


@pytest.mark.parametrize("text, expected", [
    (_MIT_TEXT, "MIT"),
    (_APACHE_TEXT, "Apache-2.0"),
    (_BSD3_TEXT, "BSD-3-Clause"),
    (_BSD2_TEXT, "BSD-2-Clause"),
    ("Some bespoke license text with no recognizable boilerplate.", None),
])
def test_classify_license_text(text, expected) -> None:
    from whatever2sbom.collectors.pip import _classify_license_text
    assert _classify_license_text(text) == expected


def test_license_falls_back_to_license_file() -> None:
    """No License-Expression/classifier, but a bundled License-File with
    recognizable MIT boilerplate (e.g. mkdocs-shadcn) resolves to "MIT"."""
    meta = _meta(**{"License-File": "LICENSE"})
    dist = _dist_for(meta, files={"licenses/LICENSE": _MIT_TEXT})
    assert _license(meta, dist) == "MIT"


def test_license_file_legacy_location() -> None:
    """Older wheels may place the License-File directly under .dist-info/
    rather than .dist-info/licenses/."""
    meta = _meta(**{"License-File": "LICENSE"})
    dist = _dist_for(meta, files={"LICENSE": _MIT_TEXT})
    assert _license(meta, dist) == "MIT"


# ── Project-URL parsing ───────────────────────────────────────────────────────────

def _meta_with_project_urls(*entries: str) -> Message:
    meta = Message()
    meta["Name"] = "foo"
    meta["Version"] = "1.0"
    for entry in entries:
        meta["Project-URL"] = entry
    return meta


def test_project_url_matches_label() -> None:
    meta = _meta_with_project_urls(
        "Documentation, https://example.org/docs",
        "Source, https://example.org/src",
        "Issues, https://example.org/issues",
    )
    assert _project_url(meta, "documentation") == "https://example.org/docs"
    assert _project_url(meta, "issue", "bug", "tracker") == "https://example.org/issues"
    assert _project_url(meta, "homepage", "home") is None


def test_to_record_homepage_falls_back_to_project_url() -> None:
    """No bare Home-page field: derive homepage from a "Homepage"-labelled
    Project-URL, splitting the URL off the "Label, URL" encoding."""
    dist = _FakeDistribution("foo", "1.0")
    dist.metadata["Project-URL"] = "Homepage, https://example.org/"
    dist.metadata["Project-URL"] = "Issues, https://example.org/issues"

    pkg = _to_record(dist)

    assert pkg.homepage == "https://example.org/"
    assert pkg.bugs == "https://example.org/issues"


def test_to_record_prefers_home_page_field() -> None:
    dist = _FakeDistribution("foo", "1.0")
    dist.metadata["Home-page"] = "https://example.org/"
    dist.metadata["Project-URL"] = "Documentation, https://example.org/docs"

    pkg = _to_record(dist)

    assert pkg.homepage == "https://example.org/"


def test_resolve_dependencies_skips_unresolvable_dep() -> None:
    """A dependency not present among installed packages is silently dropped."""
    foo = PackageRecord(name="foo", version="1.0", bom_ref="pkg:pypi/foo@1.0")
    packages = [foo]
    dists = [_FakeDistribution("foo", "1.0", requires=["not-installed>=1.0"])]

    _resolve_dependencies(packages, dists, _ENV)

    assert foo.dependency_refs == []
