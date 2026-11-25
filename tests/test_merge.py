"""Tests for the `merge` subcommand and the CycloneDX merger."""

import json

import pytest

from whatever2sbom import registry
from whatever2sbom.cli import main
from whatever2sbom.mergers.base import CollisionPolicy, MergeMode, SbomMergeError
from whatever2sbom.mergers.cyclonedx import CycloneDXMerger


def _doc(root_ref, root_name, components, dependencies):
    """A minimal schema-valid CycloneDX 1.6 document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": root_name,
                "version": "1.0",
            }
        },
        "components": components,
        "dependencies": dependencies,
    }


def _lib(ref, name, purl):
    return {"type": "library", "bom-ref": ref, "name": name, "version": "1.0", "purl": purl}


def _deps(bom, ref):
    return next((d["dependsOn"] for d in bom["dependencies"] if d["ref"] == ref), None)


@pytest.fixture
def main_doc():
    return _doc(
        "main-root", "main-app",
        [_lib("lib-a", "a", "pkg:generic/a@1.0")],
        [{"ref": "main-root", "dependsOn": ["lib-a"]}],
    )


@pytest.fixture
def incoming_doc():
    return _doc(
        "inc-root", "inc-app",
        [_lib("lib-b", "b", "pkg:generic/b@1.0")],
        [{"ref": "inc-root", "dependsOn": ["lib-b"]}],
    )


# merger behaviour

def test_flat_merge_drops_wrapper_and_reparents(main_doc, incoming_doc):
    # Default (flat): the incoming product wrapper is NOT kept as a component;
    # only its real components are merged, and its dependency edges re-parent
    # onto main's root.
    result = CycloneDXMerger().merge(main_doc, incoming_doc)
    bom = result.document

    refs = {c["bom-ref"] for c in bom["components"]}
    assert refs == {"lib-a", "lib-b"}            # no inc-root wrapper component
    assert "inc-root" not in refs
    # the wrapper's dependency (inc-root -> lib-b) re-parented onto main's root
    assert set(_deps(bom, "main-root")) == {"lib-a", "lib-b"}
    assert not any(d["ref"] == "inc-root" for d in bom["dependencies"])
    assert result.report.incoming_root_ref == "inc-root"
    assert result.report.components_added == 1   # only lib-b


def test_hierarchical_merge_keeps_wrapper_under_main_root(main_doc, incoming_doc):
    result = CycloneDXMerger(mode=MergeMode.HIERARCHICAL).merge(main_doc, incoming_doc)
    bom = result.document

    refs = {c["bom-ref"] for c in bom["components"]}
    # incoming wrapper is kept as a component alongside the libs
    assert refs == {"lib-a", "lib-b", "inc-root"}
    # wrapper attached under main's root (nothing orphaned)
    assert "inc-root" in _deps(bom, "main-root")
    # incoming's own dependency relation is preserved verbatim
    assert _deps(bom, "inc-root") == ["lib-b"]
    assert result.report.components_added == 2


def test_main_metadata_is_retained(main_doc, incoming_doc):
    main_doc["serialNumber"] = "urn:uuid:11111111-1111-1111-1111-111111111111"
    bom = CycloneDXMerger().merge(main_doc, incoming_doc).document
    assert bom["serialNumber"] == main_doc["serialNumber"]
    assert bom["metadata"]["component"]["bom-ref"] == "main-root"


def test_inputs_are_not_mutated(main_doc, incoming_doc):
    before = json.dumps(main_doc), json.dumps(incoming_doc)
    CycloneDXMerger().merge(main_doc, incoming_doc)
    assert (json.dumps(main_doc), json.dumps(incoming_doc)) == before


def test_identical_collision_is_deduplicated(main_doc):
    # incoming reuses lib-a with the same purl -> same artifact -> dedup
    incoming = _doc(
        "inc-root", "inc-app",
        [_lib("lib-a", "a", "pkg:generic/a@1.0")],
        [{"ref": "inc-root", "dependsOn": ["lib-a"]}],
    )
    result = CycloneDXMerger().merge(main_doc, incoming)
    bom = result.document

    assert [c["bom-ref"] for c in bom["components"]].count("lib-a") == 1
    assert result.report.components_deduplicated == 1
    assert not result.report.renamed_refs
    # the re-parented edge still resolves to the kept lib-a (no duplicate edge)
    assert _deps(bom, "main-root") == ["lib-a"]


def test_differing_collision_is_renamed_and_edges_rewritten(main_doc):
    # incoming reuses the ref "lib-a" for a *different* artifact
    incoming = _doc(
        "inc-root", "inc-app",
        [_lib("lib-a", "different", "pkg:generic/different@9.9")],
        [{"ref": "inc-root", "dependsOn": ["lib-a"]}],
    )
    result = CycloneDXMerger().merge(main_doc, incoming)
    bom = result.document

    assert result.report.renamed_refs == [("lib-a", "lib-a#merged")]
    refs = {c["bom-ref"] for c in bom["components"]}
    assert refs == {"lib-a", "lib-a#merged"}
    # the incoming edge was rewritten to the renamed ref and re-parented
    assert "lib-a#merged" in _deps(bom, "main-root")


def test_error_policy_rejects_differing_collision(main_doc):
    incoming = _doc(
        "inc-root", "inc-app",
        [_lib("lib-a", "different", "pkg:generic/different@9.9")],
        [{"ref": "inc-root", "dependsOn": ["lib-a"]}],
    )
    with pytest.raises(SbomMergeError, match="collision"):
        CycloneDXMerger(policy=CollisionPolicy.ERROR).merge(main_doc, incoming)


def test_detection_and_spec_version():
    assert CycloneDXMerger.detect({"bomFormat": "CycloneDX"}) is True
    assert CycloneDXMerger.detect({"spdxVersion": "SPDX-2.3"}) is False
    assert CycloneDXMerger.spec_version_of({"specVersion": "1.6"}) == "1.6"
    with pytest.raises(SbomMergeError):
        CycloneDXMerger.spec_version_of({})


def test_registry_detects_cyclonedx():
    assert registry.detect_merger({"bomFormat": "CycloneDX"}) is CycloneDXMerger
    with pytest.raises(ValueError, match="unrecognised"):
        registry.detect_merger({"not": "an sbom"})


# CLI behaviour

def _write(path, doc):
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def test_cli_merge_writes_validated_output(tmp_path, main_doc, incoming_doc):
    main_path = _write(tmp_path / "main.json", main_doc)
    inc_path  = _write(tmp_path / "incoming.json", incoming_doc)
    out_path  = tmp_path / "merged.cdx.json"

    main(["merge", main_path, inc_path, "-o", str(out_path)])

    assert out_path.exists()
    bom = json.loads(out_path.read_text(encoding="utf-8"))
    # merged output is schema-valid (the CLI validates before writing)
    assert registry.get_validator("cyclonedx", "1.6").validate(bom) == []
    # default flat mode: wrapper dropped, only real components merged
    assert {c["bom-ref"] for c in bom["components"]} == {"lib-a", "lib-b"}


def test_cli_merge_hierarchical_mode(tmp_path, main_doc, incoming_doc):
    main_path = _write(tmp_path / "main.json", main_doc)
    inc_path  = _write(tmp_path / "incoming.json", incoming_doc)
    out_path  = tmp_path / "merged.cdx.json"

    main(["merge", main_path, inc_path, "--mode", "hierarchical", "-o", str(out_path)])

    bom = json.loads(out_path.read_text(encoding="utf-8"))
    assert registry.get_validator("cyclonedx", "1.6").validate(bom) == []
    assert {c["bom-ref"] for c in bom["components"]} == {"lib-a", "lib-b", "inc-root"}


def test_cli_merge_rejects_mismatched_formats(tmp_path, main_doc, capsys):
    main_path = _write(tmp_path / "main.json", main_doc)
    spdx_path = _write(tmp_path / "other.json", {"spdxVersion": "SPDX-2.3"})
    out_path  = tmp_path / "merged.json"

    with pytest.raises(SystemExit) as exc_info:
        main(["merge", main_path, spdx_path, "-o", str(out_path)])

    assert exc_info.value.code == 1
    assert "not the same format" in capsys.readouterr().err
    assert not out_path.exists()
