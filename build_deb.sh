#!/usr/bin/env bash
# Build a .deb that installs whatever2sbom into a self-contained venv
# under /opt/whatever2sbom, with a thin wrapper at /usr/bin/whatever2sbom.
#
# All dependency wheels are bundled so `apt install ./whatever2sbom_*.deb`
# works fully offline; the venv itself is created on the target host
# during postinst so it matches the host's Python build.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PKG=whatever2sbom
ARCH=amd64
# rpds-py (a jsonschema dep) ships compiled wheels per CPython minor version,
# so this list must include whatever the target hosts run. Add new versions
# as they're released.
PYVERS=(3.10 3.11 3.12 3.13 3.14)
PLATFORM=manylinux2014_x86_64

rm -rf dist build/deb
python3 -m pip install --quiet --upgrade build
python3 -m build --wheel

WHEEL="$(ls dist/${PKG}-*.whl)"
VERSION="$(basename "$WHEEL" | cut -d- -f2)"

PKGROOT="build/deb/${PKG}_${VERSION}_${ARCH}"
WHEELDIR="$PKGROOT/opt/$PKG/wheels"

DOCDIR="$PKGROOT/usr/share/doc/$PKG"
MANDIR="$PKGROOT/usr/share/man/man1"

mkdir -p "$PKGROOT/DEBIAN" "$WHEELDIR" "$PKGROOT/usr/bin" "$DOCDIR" "$MANDIR"

cp "$WHEEL" "$WHEELDIR/"

for pv in "${PYVERS[@]}"; do
    abi="cp${pv//./}"
    python3 -m pip download --quiet \
        --only-binary=:all: \
        --platform "$PLATFORM" \
        --python-version "$pv" \
        --implementation cp \
        --abi "$abi" \
        -d "$WHEELDIR" \
        "$WHEEL"
done

install -m 755 debian/wrapper "$PKGROOT/usr/bin/$PKG"
install -m 755 debian/postinst "$PKGROOT/DEBIAN/postinst"
install -m 755 debian/postrm "$PKGROOT/DEBIAN/postrm"
install -m 644 debian/copyright "$DOCDIR/copyright"

# Section 1 manpage, version-substituted (like control.in) and gzip -9n
# (no timestamp) into the standard man path.
sed -e "s/__VERSION__/$VERSION/" debian/whatever2sbom.1 \
    | gzip -9n > "$MANDIR/$PKG.1.gz"

SIZE="$(du -sk "$PKGROOT" | cut -f1)"
sed -e "s/__VERSION__/$VERSION/" -e "s/__ARCH__/$ARCH/" -e "s/__SIZE__/$SIZE/" \
    debian/control.in > "$PKGROOT/DEBIAN/control"

dpkg-deb --root-owner-group --build "$PKGROOT"

echo ""
echo "Package ready: ${PKGROOT}.deb"
echo ""
echo "Install:  sudo apt install ./$(basename "$PKGROOT").deb"
echo "Run:      whatever2sbom --product-supplier <name>"
