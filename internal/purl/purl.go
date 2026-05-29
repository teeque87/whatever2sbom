// Package purl provides PURL-spec-compliant percent-encoding.
//
// The PURL spec keeps a small set of characters unencoded that Go's
// net/url.QueryEscape escapes (notably ":", "~"), and vice versa.
// QuoteVersion replicates Python's urllib.parse.quote(safe=".-:~") so that
// versions like "2.34+dfsg-1" become "2.34%2Bdfsg-1".
package purl

import "strings"

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
