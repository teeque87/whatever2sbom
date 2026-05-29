package formatter

import (
	"testing"
)

func TestNormalizeDepName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"libc6:amd64", "libc6"},
		{"libc6 (>= 2.17)", "libc6"},
		{"libc6 [amd64 i386]", "libc6"},
		{"libc6:amd64 (>= 2.17)", "libc6"},
		{"  awk  ", "awk"},
	}
	for _, tc := range cases {
		if got := normalizeDepName(tc.in); got != tc.want {
			t.Errorf("normalizeDepName(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveDeps_DirectHit(t *testing.T) {
	nameToRef := map[string]string{"libc6": "pkg:deb/debian/libc6@2.36"}
	got := resolveDeps("libc6 (>= 2.17)", nameToRef, nil)
	want := []string{"pkg:deb/debian/libc6@2.36"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolveDeps_ArchQualifier(t *testing.T) {
	nameToRef := map[string]string{"libc6": "pkg:deb/debian/libc6@2.36"}
	got := resolveDeps("libc6:amd64 (>= 2.17)", nameToRef, nil)
	want := []string{"pkg:deb/debian/libc6@2.36"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolveDeps_VirtualPackage(t *testing.T) {
	nameToRef := map[string]string{"mawk": "pkg:deb/debian/mawk@1.3"}
	providesMap := map[string]string{"awk": "pkg:deb/debian/mawk@1.3"}
	got := resolveDeps("awk", nameToRef, providesMap)
	want := []string{"pkg:deb/debian/mawk@1.3"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolveDeps_AlternativesFirstWins(t *testing.T) {
	nameToRef := map[string]string{"mawk": "pkg:deb/debian/mawk@1.3"}
	got := resolveDeps("gawk | mawk | nawk", nameToRef, nil)
	want := []string{"pkg:deb/debian/mawk@1.3"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolveDeps_MultipleGroups(t *testing.T) {
	nameToRef := map[string]string{
		"libc6": "pkg:deb/debian/libc6@2.36",
		"bash":  "pkg:deb/debian/bash@5.2",
	}
	got := resolveDeps("libc6, bash", nameToRef, nil)
	want := []string{
		"pkg:deb/debian/libc6@2.36",
		"pkg:deb/debian/bash@5.2",
	}
	if !equalStrings(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
