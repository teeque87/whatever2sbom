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
