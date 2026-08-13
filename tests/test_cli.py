"""Tests for CLI-level argument validation in cli.main()."""

import pytest

from whatever2sbom.cli import main


def test_help_shows_only_default_system(capsys) -> None:
    """--help with no --system shows only the default (dpkg) system's options,
    not every system's, with a pointer to the others."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "dpkg system options" in out
    assert "npm system options" not in out
    assert "pip system options" not in out
    assert "other systems: npm, pip" in out


def test_help_shows_only_selected_system(capsys) -> None:
    """--system npm --help shows npm's options instead of dpkg's."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--system", "npm", "--help"])

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "npm system options" in out
    assert "--lockfile" in out
    assert "dpkg system options" not in out
    assert "pip system options" not in out
    assert "other systems: dpkg, pip" in out


def test_invalid_system_still_errors_with_choices(capsys) -> None:
    """An unknown --system falls back to the default for parser construction
    but is still rejected with the proper choices list."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--system", "bogus", "--product-supplier", "Acme GmbH"])

    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice: 'bogus'" in err


def test_pip_requires_product_name(capsys) -> None:
    """--system pip has no host-OS fallback for metadata.component, so
    --product-name must be given explicitly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--system", "pip", "--product-supplier", "Acme GmbH"])

    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "--product-name is required for --system pip" in err


def test_pip_requires_product_version(capsys) -> None:
    """The product version isn't discoverable from a venv scan, so --system pip
    requires it explicitly (once --product-name is supplied)."""
    with pytest.raises(SystemExit) as exc_info:
        main([
            "--system", "pip",
            "--product-supplier", "Acme GmbH",
            "--product-name", "app",
        ])

    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "--product-version is required for --system pip" in err
