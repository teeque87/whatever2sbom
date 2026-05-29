package enricher

import "testing"

// A realistic DEP-5 copyright file with multiple stanzas — what most
// well-packaged libraries ship in /usr/share/doc/<pkg>/copyright.
const dep5Realistic = `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: libfoo
Upstream-Contact: foo@example.com
Source: https://example.com/libfoo

Files: *
Copyright: 2018-2024 The Foo Authors
License: GPL-2+

Files: src/vendor/*
Copyright: 2017 Vendor Inc.
License: Apache-2.0

Files: docs/*.md
Copyright: 2020 Doc Team
License: CC-BY-SA-4.0

Files: debian/*
Copyright: 2019-2024 Debian Maintainer <debian@example.com>
License: MIT

License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.

License: MIT
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software.
`

// A representative apt-cache show output — a few stanzas, each with the
// hash / size / filename fields we extract.
const aptCacheSample = `Package: libfoo
Version: 1.2.3-1
Architecture: amd64
Maintainer: Debian Foo Maintainers <foo@lists.debian.org>
Installed-Size: 412
Depends: libc6 (>= 2.34)
Filename: pool/main/libf/libfoo/libfoo_1.2.3-1_amd64.deb
Size: 84212
MD5sum: 9b74c9897bac770ffc029102a200c5de
SHA1: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
SHA512: 8aefb06c426e07a0a671a1e2488b4858d694a730489a9c83f8cba7ae6f5c45d8c54a2e9e6a4e1e0fe0c25b0c2e1d8c0e9d3b8c9e0b2f8c0e8c9e2f8c4c8d9e2f8

Package: libbar
Version: 2.0.0
Architecture: amd64
Maintainer: Bar Team <bar@example.com>
Installed-Size: 1024
Depends: libfoo (>= 1.0)
Filename: pool/main/libb/libbar/libbar_2.0.0_amd64.deb
Size: 250000
MD5sum: 5d41402abc4b2a76b9719d911017c592
SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA256: 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9
SHA512: 1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75
`

// A long realistic dpkg-query block, using the same key=value format the
// collector emits via --showformat.
const dpkgRecord = `package=libfoo
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

func BenchmarkParseDEP5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = parseDEP5(dep5Realistic)
	}
}

func BenchmarkParseAptStanzas(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = parseAptStanzas(aptCacheSample)
	}
}
