"""Tests for CLI-level argument validation in cli.main()."""

import pytest

from whatever2sbom.cli import main


def test_pip_requires_product_name(capsys) -> None:
    """--system pip has no host-OS fallback for metadata.component, so
    --product-name must be given explicitly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--system", "pip", "--product-supplier", "Acme GmbH"])

    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "--product-name is required for --system pip" in err
