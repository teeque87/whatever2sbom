"""Tests for the plugin system: config parsing, discovery/loading, the
built-in patch-purl plugin, and pipeline integration."""

import json

import pytest

from whatever2sbom.pipeline import SbomPipeline
from whatever2sbom.plugins import (
    PluginError,
    load_plugin,
    parse_plugin_configs,
    plugin_search_path,
)


# config parsing

def test_parse_inline_config_scalar_and_list() -> None:
    configs = parse_plugin_configs(
        ["patch-purl:namespace=acme", "patch-purl:packages=requests,urllib3"],
        None,
    )
    assert configs == {"patch-purl": {"namespace": "acme", "packages": ["requests", "urllib3"]}}


def test_parse_config_file_then_inline_override(tmp_path) -> None:
    cfg = tmp_path / "plugins.json"
    cfg.write_text(
        json.dumps({"patch-purl": {"namespace": "from-file", "packages": ["a"]}}),
        encoding="utf-8",
    )
    configs = parse_plugin_configs(["patch-purl:namespace=inline"], str(cfg))
    # inline wins on conflict; file-only keys survive
    assert configs == {"patch-purl": {"namespace": "inline", "packages": ["a"]}}


@pytest.mark.parametrize("bad", ["no-colon-or-eq", "name:no-equals", "name=missing-colon"])
def test_parse_inline_config_rejects_malformed(bad) -> None:
    with pytest.raises(PluginError):
        parse_plugin_configs([bad], None)


def test_parse_config_file_must_be_object_of_objects(tmp_path) -> None:
    cfg = tmp_path / "bad.json"
    cfg.write_text(json.dumps({"patch-purl": "not-an-object"}), encoding="utf-8")
    with pytest.raises(PluginError):
        parse_plugin_configs(None, str(cfg))


# discovery / loading

def test_search_path_includes_builtin_dir() -> None:
    path = plugin_search_path()
    assert any(p.name == "builtin" for p in path)


def test_env_var_takes_precedence(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WHATEVER2SBOM_PLUGIN_PATH", str(tmp_path))
    assert plugin_search_path()[0] == tmp_path


def test_load_unknown_plugin_raises() -> None:
    with pytest.raises(PluginError, match="not found"):
        load_plugin("does-not-exist")


@pytest.mark.parametrize("name", ["../evil", "sub/dir", ".", ""])
def test_reject_path_like_names(name) -> None:
    with pytest.raises(PluginError, match="invalid plugin name|not found"):
        load_plugin(name)


def test_load_custom_plugin_from_env_dir(tmp_path, monkeypatch) -> None:
    (tmp_path / "tagger.py").write_text(
        "def apply(bom, config):\n"
        "    bom['tagged'] = config.get('label', 'default')\n"
        "    return bom\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("WHATEVER2SBOM_PLUGIN_PATH", str(tmp_path))
    plugin = load_plugin("tagger", {"label": "x"})
    assert plugin.run({}) == {"tagged": "x"}


def test_load_plugin_without_apply_raises(tmp_path, monkeypatch) -> None:
    (tmp_path / "noapply.py").write_text("X = 1\n", encoding="utf-8")
    monkeypatch.setenv("WHATEVER2SBOM_PLUGIN_PATH", str(tmp_path))
    with pytest.raises(PluginError, match="apply"):
        load_plugin("noapply")


def test_run_rejects_non_dict_return(tmp_path, monkeypatch) -> None:
    (tmp_path / "bad.py").write_text("def apply(bom, config):\n    return 42\n", encoding="utf-8")
    monkeypatch.setenv("WHATEVER2SBOM_PLUGIN_PATH", str(tmp_path))
    with pytest.raises(PluginError, match="must return"):
        load_plugin("bad").run({})


def test_run_wraps_plugin_exception(tmp_path, monkeypatch) -> None:
    (tmp_path / "boom.py").write_text(
        "def apply(bom, config):\n    raise ValueError('nope')\n", encoding="utf-8"
    )
    monkeypatch.setenv("WHATEVER2SBOM_PLUGIN_PATH", str(tmp_path))
    with pytest.raises(PluginError, match="nope"):
        load_plugin("boom").run({})


# built-in patch-purl

def _bom(*purls: str) -> dict:
    return {
        "components": [
            {"name": purl.split("/")[-1].split("@")[0], "purl": purl} for purl in purls
        ]
    }


def test_patch_purl_replaces_existing_namespace_and_keeps_qualifiers() -> None:
    plugin = load_plugin("patch-purl", {"namespace": "acme", "packages": ["bash"]})
    bom = {"components": [{"name": "bash", "purl": "pkg:deb/debian/bash@5.1?arch=amd64&distro=bookworm"}]}
    out = plugin.run(bom)
    assert out["components"][0]["purl"] == "pkg:deb/acme/bash@5.1?arch=amd64&distro=bookworm"


def test_patch_purl_leaves_namespaceless_purl_untouched() -> None:
    # pypi PURLs have no namespace, so there's nothing to replace.
    plugin = load_plugin("patch-purl", {"namespace": "acme", "packages": ["requests"]})
    bom = {"components": [{"name": "requests", "purl": "pkg:pypi/requests@2.31.0"}]}
    out = plugin.run(bom)
    assert out["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"


def test_patch_purl_only_touches_named_packages() -> None:
    plugin = load_plugin("patch-purl", {"namespace": "acme", "packages": ["bash"]})
    bom = {
        "components": [
            {"name": "bash", "purl": "pkg:deb/debian/bash@5.1"},
            {"name": "coreutils", "purl": "pkg:deb/debian/coreutils@9.1"},
        ]
    }
    out = plugin.run(bom)
    assert out["components"][0]["purl"] == "pkg:deb/acme/bash@5.1"
    assert out["components"][1]["purl"] == "pkg:deb/debian/coreutils@9.1"  # untouched


def test_patch_purl_loose_prefix_matching() -> None:
    # "linux-hwe" should match the base package and its versioned binaries,
    # but not an unrelated name that merely shares the "linux" stem.
    plugin = load_plugin("patch-purl", {"namespace": "acme", "packages": ["linux-hwe"]})
    bom = {
        "components": [
            {"name": "linux-hwe", "purl": "pkg:deb/debian/linux-hwe@6.8"},
            {"name": "linux-hwe-4828.2.1.1", "purl": "pkg:deb/debian/linux-hwe-4828.2.1.1@6.8"},
            {"name": "linux-firmware", "purl": "pkg:deb/debian/linux-firmware@1.0"},
        ]
    }
    out = plugin.run(bom)
    assert out["components"][0]["purl"] == "pkg:deb/acme/linux-hwe@6.8"
    assert out["components"][1]["purl"] == "pkg:deb/acme/linux-hwe-4828.2.1.1@6.8"
    assert out["components"][2]["purl"] == "pkg:deb/debian/linux-firmware@1.0"  # untouched


@pytest.mark.parametrize("config", [{}, {"namespace": "acme"}, {"packages": ["bash"]}])
def test_patch_purl_requires_namespace_and_packages(config) -> None:
    plugin = load_plugin("patch-purl", config)
    with pytest.raises(PluginError, match="namespace.*packages|requires"):
        plugin.run(_bom("pkg:deb/debian/bash@5.1"))


# pipeline integration

class _StubCollector:
    name = "stub"

    def collect(self):
        return []


class _StubFormatter:
    name = "stub"

    def format(self, packages):
        return {"components": [{"name": "bash", "purl": "pkg:deb/debian/bash@5.1"}]}


class _RecordingValidator:
    name = "stub"

    def __init__(self):
        self.seen = None

    def validate(self, bom):
        self.seen = bom
        return []


def test_pipeline_runs_plugin_before_validation() -> None:
    validator = _RecordingValidator()
    plugin = load_plugin("patch-purl", {"namespace": "acme", "packages": ["bash"]})
    pipeline = SbomPipeline(
        collector=_StubCollector(),
        enrichers=[],
        formatter=_StubFormatter(),
        validators=[validator],
        plugins=[plugin],
    )
    bom = pipeline.run()
    patched = "pkg:deb/acme/bash@5.1"
    assert bom["components"][0]["purl"] == patched
    # validation saw the already-patched document
    assert validator.seen["components"][0]["purl"] == patched
