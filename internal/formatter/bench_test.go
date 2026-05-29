package formatter

import (
	"testing"

	"whatever2sbom/internal/model"
)

// A representative Debian Depends field — multiple comma-separated groups,
// one alternative group, version constraints, an arch qualifier.
const dependsRealistic = "libc6 (>= 2.34), libssl3 (>= 3.0), libfoo (>= 1.0) | libbar, debconf (>= 0.5) | debconf-2.0, mawk:amd64"

func BenchmarkResolveDeps(b *testing.B) {
	nameToRef := map[string]string{
		"libc6":   "pkg:deb/debian/libc6@2.36",
		"libssl3": "pkg:deb/debian/libssl3@3.0.5",
		"libbar":  "pkg:deb/debian/libbar@2.0.0",
		"debconf": "pkg:deb/debian/debconf@1.5.79",
		"mawk":    "pkg:deb/debian/mawk@1.3.4",
	}
	provides := map[string]string{
		"debconf-2.0": "pkg:deb/debian/debconf@1.5.79",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resolveDeps(dependsRealistic, nameToRef, provides)
	}
}

func BenchmarkBuildPURL(b *testing.B) {
	// Version with "+" forces percent-encoding — the slow path.
	p := &model.Package{
		Name:         "libfoo",
		Version:      "2.34+dfsg-1ubuntu1.2",
		Architecture: "amd64",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildPURL(p, "debian", "bookworm")
	}
}

func BenchmarkNormalizeDepName(b *testing.B) {
	const token = "libfoo:amd64 (>= 1.2.3) [amd64 i386]"
	for i := 0; i < b.N; i++ {
		_ = normalizeDepName(token)
	}
}
