package enricher

import (
	"testing"
)

const dep5Simple = `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: mylib

Files: *
Copyright: 2020 Someone
License: GPL-2+

Files: debian/*
Copyright: 2020 Packager
License: MIT
`

const dep5NoWildcard = `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: src/*.c
Copyright: 2019 Author
License: Apache-2.0
`

func TestParseDEP5_WildcardFirst(t *testing.T) {
	got := parseDEP5(dep5Simple)
	if len(got) == 0 || got[0] != "GPL-2+" {
		t.Fatalf("expected GPL-2+ first, got %v", got)
	}
	if !contains(got, "MIT") {
		t.Fatalf("expected MIT in result, got %v", got)
	}
}

func TestParseDEP5_NoWildcard(t *testing.T) {
	got := parseDEP5(dep5NoWildcard)
	want := []string{"Apache-2.0"}
	if !equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseDEP5_Deduplication(t *testing.T) {
	content := `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 A
License: MIT

Files: extra/*
Copyright: 2020 B
License: MIT
`
	got := parseDEP5(content)
	count := 0
	for _, v := range got {
		if v == "MIT" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected MIT once, got %d times: %v", count, got)
	}
}

func TestDebianToSPDXMapping(t *testing.T) {
	cases := map[string]string{
		"GPL-2+":   "GPL-2.0-or-later",
		"Apache-2": "Apache-2.0",
		"MIT":      "MIT",
	}
	for in, want := range cases {
		if got := debianToSPDX[in]; got != want {
			t.Errorf("debianToSPDX[%q] = %q; want %q", in, got, want)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
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
