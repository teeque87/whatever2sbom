"""Tests for dpkg package exclusion: file parsing, exact/glob matching, and the
unmatched-pattern report."""

import argparse

import pytest

from whatever2sbom.collectors.dpkg import _ExcludeFilter, read_exclude_file
from whatever2sbom.models import PackageRecord
from whatever2sbom.systems.dpkg import DpkgSystem


def _pkgs(*names: str) -> list[PackageRecord]:
    return [PackageRecord(name=n, version="1.0") for n in names]


def _kept_names(patterns: list[str], names: list[str]) -> list[str]:
    f = _ExcludeFilter(patterns)
    return [p.name for p in f.keep(_pkgs(*names))]


# read_exclude_file

def test_read_exclude_file_strips_comments_and_blanks(tmp_path) -> None:
    f = tmp_path / "excludes.txt"
    f.write_text(
        "# kernel images we ship ourselves\n"
        "linux-image-*\n"
        "\n"
        "   \n"
        "snapd            # not relevant for this image\n"
        "  python3-foo  \n",
        encoding="utf-8",
    )
    assert read_exclude_file(str(f)) == ["linux-image-*", "snapd", "python3-foo"]


def test_read_exclude_file_missing_raises_runtime_error() -> None:
    with pytest.raises(RuntimeError, match="could not read --exclude-file"):
        read_exclude_file("/no/such/file.txt")


# exact matching

def test_exact_match_only_removes_named_package() -> None:
    kept = _kept_names(["snapd"], ["snapd", "snapd-glib", "bash"])
    # exact: "snapd" must NOT take "snapd-glib" (that would be prefix matching)
    assert kept == ["snapd-glib", "bash"]


# glob matching

def test_glob_star_matches_family() -> None:
    kept = _kept_names(
        ["linux-image-*"],
        ["linux-image-6.8.0-generic", "linux-image-unsigned-6.8.0", "linux-headers-6.8.0"],
    )
    assert kept == ["linux-headers-6.8.0"]


def test_glob_suffix_and_question_mark() -> None:
    kept = _kept_names(["*-dbg", "libc?"], ["foo-dbg", "bar", "libc6", "libcaa"])
    # "*-dbg" drops foo-dbg; "libc?" drops the single-trailing-char libc6 but not libcaa
    assert kept == ["bar", "libcaa"]


def test_glob_is_case_sensitive() -> None:
    # fnmatchcase: an upper-case pattern does not match a lower-case name.
    assert _kept_names(["LINUX-*"], ["linux-image-6.8"]) == ["linux-image-6.8"]


# combined + unmatched report

def test_exact_and_glob_combined() -> None:
    f = _ExcludeFilter(["bash", "linux-image-*"])
    kept = [p.name for p in f.keep(_pkgs("bash", "linux-image-6.8", "coreutils"))]
    assert kept == ["coreutils"]
    assert f.removed == 2
    assert f.unmatched() == []


def test_unmatched_patterns_reported() -> None:
    f = _ExcludeFilter(["bash", "does-not-exist", "ghost-*"])
    f.keep(_pkgs("bash", "coreutils"))
    # order preserved, only the patterns that matched nothing
    assert f.unmatched() == ["does-not-exist", "ghost-*"]


def test_duplicate_patterns_deduped_in_report() -> None:
    f = _ExcludeFilter(["bash", "bash"])
    f.keep(_pkgs("coreutils"))
    assert f.unmatched() == ["bash"]


# CLI wiring

def test_dpkg_system_forwards_exclude_args_to_collector() -> None:
    args = argparse.Namespace(distro=None, exclude=["bash"], exclude_file="excludes.txt")
    collector = DpkgSystem().make_collector(args)
    assert collector._exclude == ["bash"]
    assert collector._exclude_file == "excludes.txt"


def test_dpkg_system_handles_absent_exclude_args() -> None:
    # make_collector must tolerate a namespace without exclude attrs.
    collector = DpkgSystem().make_collector(argparse.Namespace(distro=None))
    assert collector._exclude is None
    assert collector._exclude_file is None
