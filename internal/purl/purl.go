// Package purl provides PURL-spec-compliant percent-encoding and the
// per-ecosystem PURL builders.
//
// Each ecosystem has its own coordinate rules, so each gets its own builder
// (Deb today; PyPI, NPM, … slot in here as siblings later). Collectors call the
// builder for their ecosystem and store the result on model.Package; formatters
// stay ecosystem-blind and just emit the finished string.
//
// The PURL spec keeps a small set of characters unencoded that Go's
// net/url.QueryEscape escapes (notably ":", "~"), and vice versa.
// QuoteVersion replicates Python's urllib.parse.quote(safe=".-:~") so that
// versions like "2.34+dfsg-1" become "2.34%2Bdfsg-1".
package purl

import "strings"

// Deb builds a Debian/Ubuntu package-url:
//
//	pkg:deb/<distro>/<name>@<version>?arch=<arch>&distro=<codename>
//
// The version is percent-encoded per QuoteVersion. The arch and codename
// qualifiers are optional: an empty arch (or the dpkg meta-arch "all") omits the
// arch qualifier, and an empty codename omits distro. Pass arch="source" to
// produce the source coordinate that Debian/Ubuntu security data is keyed on.
func Deb(distro, name, version, arch, codename string) string {
	out := "pkg:deb/" + distro + "/" + name + "@" + QuoteVersion(version)
	var qs []string
	if arch != "" && arch != "all" {
		qs = append(qs, "arch="+arch)
	}
	if codename != "" {
		qs = append(qs, "distro="+codename)
	}
	if len(qs) > 0 {
		out += "?" + strings.Join(qs, "&")
	}
	return out
}

// QuoteVersion percent-encodes everything except unreserved chars plus
// the additional safe set (. - : ~). Notably, "+" is encoded — required by
// OSV.dev and other PURL consumers.
func QuoteVersion(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isSafe(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex(c >> 4))
			b.WriteByte(hex(c & 0x0f))
		}
	}
	return b.String()
}

func isSafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_' || c == '.' || c == '-' || c == ':' || c == '~':
		return true
	}
	return false
}

func hex(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}
