package purl

import "testing"

func TestQuoteVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		// Unreserved chars + . - : ~ pass through untouched.
		{"1.2.3", "1.2.3"},
		{"2.34-1", "2.34-1"},
		{"1:2.34-1", "1:2.34-1"},
		{"1.2.3~rc1", "1.2.3~rc1"},
		// "+" must be percent-encoded — required by OSV.dev.
		{"2.34+dfsg-1", "2.34%2Bdfsg-1"},
		// Other reserved chars also encoded.
		{"foo/bar", "foo%2Fbar"},
		{"a b", "a%20b"},
	}
	for _, tc := range cases {
		if got := QuoteVersion(tc.in); got != tc.want {
			t.Errorf("QuoteVersion(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestDeb(t *testing.T) {
	cases := []struct {
		name                                 string
		distro, pkg, version, arch, codename string
		want                                 string
	}{
		{"full coordinate", "ubuntu", "poppler", "26.01.0-2build2", "source", "resolute",
			"pkg:deb/ubuntu/poppler@26.01.0-2build2?arch=source&distro=resolute"},
		{"version is percent-encoded (+ -> %2B)", "ubuntu", "expat", "2.7.4+really-1", "source", "resolute",
			"pkg:deb/ubuntu/expat@2.7.4%2Breally-1?arch=source&distro=resolute"},
		{"arch=all omitted", "ubuntu", "fonts-foo", "1.0-1", "all", "resolute",
			"pkg:deb/ubuntu/fonts-foo@1.0-1?distro=resolute"},
		{"empty arch omitted", "ubuntu", "foo", "1.0-1", "", "resolute",
			"pkg:deb/ubuntu/foo@1.0-1?distro=resolute"},
		{"empty codename omits distro qualifier", "debian", "bar", "2.0", "amd64", "",
			"pkg:deb/debian/bar@2.0?arch=amd64"},
		{"no qualifiers at all", "debian", "baz", "3.0", "", "",
			"pkg:deb/debian/baz@3.0"},
	}
	for _, tc := range cases {
		if got := Deb(tc.distro, tc.pkg, tc.version, tc.arch, tc.codename); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
