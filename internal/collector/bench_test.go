package collector

import "testing"

// A representative dpkg-query record block, as produced by the format string
// in buildDpkgFormat(). Includes a multi-line description (continuation lines).
const dpkgBlock = `package=libfoo
version=1.2.3-1
architecture=amd64
source=
section=libs
priority=optional
installed_size=412
maintainer=Debian Foo Maintainers <foo@lists.debian.org>
homepage=https://example.com/libfoo
origin=Debian
bugs=https://bugs.debian.org/libfoo
essential=
multi_arch=same
depends=libc6 (>= 2.34), libssl3 (>= 3.0)
pre_depends=
provides=libfoo-1
description=A foo library
 This library does foo. It is foo-y. It uses libssl and libc.
 .
 The library supports many flavours of foo.
filename=pool/main/libf/libfoo/libfoo_1.2.3-1_amd64.deb
size=84212
md5sum=9b74c9897bac770ffc029102a200c5de
sha256=2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
status_want=install
status_status=installed`

func BenchmarkParseDpkgRecord(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = parseDpkgRecord(dpkgBlock)
	}
}
