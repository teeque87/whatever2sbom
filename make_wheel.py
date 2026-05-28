#!/usr/bin/env python3
"""Build whatever2sbom into a distributable wheel."""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
DIST = ROOT / "dist"


def clean() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
        print(f"Cleaned {DIST}")


def build() -> Path:
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel"],
        cwd=ROOT,
        check=True,
    )
    wheels = list(DIST.glob("*.whl"))
    if not wheels:
        raise RuntimeError("Build succeeded but no .whl found in dist/")
    return wheels[0]


if __name__ == "__main__":
    clean()
    wheel = build()
    print(f"\nWheel ready: {wheel}")
    print(f"\nInstall with:")
    print(f"  pip install {wheel.name}")
    print(f"\nTransfer and install on a remote host:")
    print(f"  scp {wheel} user@host:/tmp/")
    print(f"  ssh user@host pip install /tmp/{wheel.name}")
