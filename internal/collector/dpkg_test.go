package collector

import (
	"testing"

	"whatever2sbom/internal/model"
)

func TestDebPURLs(t *testing.T) {
	cases := []struct {
		name       string
		pkg        model.Package
		wantPURL   string // matchable source coordinate
		wantBomRef string // unique per-binary coordinate
	}{
		{
			name:       "binary differs from source — match key uses source coord + arch=source",
			pkg:        model.Package{Name: "poppler-utils", Version: "26.01.0-2build2", Architecture: "amd64", SourceName: "poppler", SourceVersion: "26.01.0-2build2"},
			wantPURL:   "pkg:deb/ubuntu/poppler@26.01.0-2build2?arch=source&distro=resolute",
			wantBomRef: "pkg:deb/ubuntu/poppler-utils@26.01.0-2build2?arch=amd64&distro=resolute",
		},
		{
			name:       "source version carries epoch / strips binNMU",
			pkg:        model.Package{Name: "libdevmapper1.02.1", Version: "2:1.02.205-2ubuntu3", Architecture: "amd64", SourceName: "lvm2", SourceVersion: "2.03.31-2ubuntu3"},
			wantPURL:   "pkg:deb/ubuntu/lvm2@2.03.31-2ubuntu3?arch=source&distro=resolute",
			wantBomRef: "pkg:deb/ubuntu/libdevmapper1.02.1@2:1.02.205-2ubuntu3?arch=amd64&distro=resolute",
		},
		{
			name:       "no distinct source — falls back to binary name/version",
			pkg:        model.Package{Name: "bash", Version: "5.3-2ubuntu1", Architecture: "amd64"},
			wantPURL:   "pkg:deb/ubuntu/bash@5.3-2ubuntu1?arch=source&distro=resolute",
			wantBomRef: "pkg:deb/ubuntu/bash@5.3-2ubuntu1?arch=amd64&distro=resolute",
		},
		{
			name:       "arch=all is omitted from the bom-ref",
			pkg:        model.Package{Name: "fonts-foo", Version: "1.0-1", Architecture: "all", SourceName: "foo", SourceVersion: "1.0-1"},
			wantPURL:   "pkg:deb/ubuntu/foo@1.0-1?arch=source&distro=resolute",
			wantBomRef: "pkg:deb/ubuntu/fonts-foo@1.0-1?distro=resolute",
		},
	}
	for _, tc := range cases {
		p := tc.pkg
		debPURLs(&p, "ubuntu", "resolute")
		if p.PURL != tc.wantPURL {
			t.Errorf("%s PURL:\n got %q\nwant %q", tc.name, p.PURL, tc.wantPURL)
		}
		if p.BomRef != tc.wantBomRef {
			t.Errorf("%s BomRef:\n got %q\nwant %q", tc.name, p.BomRef, tc.wantBomRef)
		}
	}
}

func TestResolveDistro(t *testing.T) {
	cases := []struct {
		name         string
		override     string
		osInfo       map[string]string
		wantDistro   string
		wantCodename string
	}{
		{"override wins", "ubuntu", map[string]string{"id": "debian", "version_codename": "bookworm"}, "ubuntu", "bookworm"},
		{"derive from os-release", "", map[string]string{"id": "ubuntu", "version_codename": "resolute"}, "ubuntu", "resolute"},
		{"fallback to debian", "", map[string]string{}, "debian", ""},
	}
	for _, tc := range cases {
		d, c := resolveDistro(tc.override, tc.osInfo)
		if d != tc.wantDistro || c != tc.wantCodename {
			t.Errorf("%s: got (%q,%q) want (%q,%q)", tc.name, d, c, tc.wantDistro, tc.wantCodename)
		}
	}
}
