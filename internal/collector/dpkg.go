package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"whatever2sbom/internal/model"
	"whatever2sbom/internal/osinfo"
	"whatever2sbom/internal/purl"
)

// Fields requested from dpkg-query. Status fields are used only for filtering;
// SHA-1 and SHA-512 are not in the dpkg DB — they come from the apt-cache enricher.
var dpkgFields = []struct {
	key, expr string
}{
	{"package", "${binary:Package}"},
	{"version", "${Version}"},
	{"architecture", "${Architecture}"},
	{"source", "${Source}"},
	// Resolved source identity. ${source:Package}/${source:Version} fall back to
	// the binary name/version when a package has no distinct source, and crucially
	// carry the source version *with epoch* and without binNMU suffixes — which is
	// exactly the coordinate OSV / Ubuntu security data is published against.
	{"source_package", "${source:Package}"},
	{"source_version", "${source:Version}"},
	{"section", "${Section}"},
	{"priority", "${Priority}"},
	{"installed_size", "${Installed-Size}"},
	{"maintainer", "${Maintainer}"},
	{"homepage", "${Homepage}"},
	{"origin", "${Origin}"},
	{"bugs", "${Bugs}"},
	{"essential", "${Essential}"},
	{"multi_arch", "${Multi-Arch}"},
	{"depends", "${Depends}"},
	{"pre_depends", "${Pre-Depends}"},
	{"provides", "${Provides}"},
	{"description", "${Description}"},
	{"filename", "${Filename}"},
	{"size", "${Size}"},
	{"md5sum", "${MD5sum}"},
	{"sha256", "${SHA256}"},
	{"status_want", "${db:Status-Want}"},
	{"status_status", "${db:Status-Status}"},
}

const dpkgRecordSep = "---RECORD_END---"

// DpkgCollector collects installed packages via `dpkg-query -W`.
type DpkgCollector struct {
	// InstalledOnly drops packages whose status is not "install installed".
	InstalledOnly bool
	// Distro overrides the OS distro identifier used in package PURLs. Empty
	// means "derive from /etc/os-release" (falling back to "debian").
	Distro string
}

// NewDpkg returns a collector that filters to installed packages. The distro
// argument is the optional PURL distro override (empty = derive from os-release).
func NewDpkg(distro string) *DpkgCollector {
	return &DpkgCollector{InstalledOnly: true, Distro: distro}
}

// Name implements Collector.
func (DpkgCollector) Name() string { return "dpkg" }

// Collect runs dpkg-query and parses each record into a model.Package.
func (c *DpkgCollector) Collect() ([]*model.Package, error) {
	fmtStr := buildDpkgFormat()
	cmd := exec.Command("dpkg-query", "-W", "--showformat="+fmtStr)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("dpkg-query failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		// FileNotFoundError equivalent
		return nil, fmt.Errorf("dpkg-query not found — is this a Debian/Ubuntu system?")
	}

	var pkgs []*model.Package
	for _, block := range strings.Split(string(out), dpkgRecordSep) {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		raw := parseDpkgRecord(block)
		if raw["package"] == "" {
			continue
		}
		if c.InstalledOnly {
			if raw["status_want"] != "install" || raw["status_status"] != "installed" {
				continue
			}
		}
		pkgs = append(pkgs, toPackage(raw))
	}

	// PURLs are an ecosystem fact, so the collector owns them: deb coordinates
	// live here, and the formatter just emits p.PURL / p.BomRef verbatim.
	distro, codename := resolveDistro(c.Distro, osinfo.Get())
	for _, p := range pkgs {
		debPURLs(p, distro, codename)
	}

	slog.Info(fmt.Sprintf("  ← %d packages found", len(pkgs)))
	return pkgs, nil
}

// resolveDistro derives the PURL distro id and the distro codename, honoring an
// explicit override. Mirrors the previous formatter logic so output is unchanged.
func resolveDistro(override string, osInfo map[string]string) (distro, codename string) {
	distro = override
	if distro == "" {
		if id := osInfo["id"]; id != "" {
			distro = id
		} else {
			distro = "debian"
		}
	}
	return distro, osInfo["version_codename"]
}

// debPURLs fills the matchable PURL and the unique bom-ref for one package using
// Debian/Ubuntu coordinate rules:
//   - BomRef: the per-binary coordinate (name + arch) — unique dep-graph node id.
//   - PURL:   the source coordinate with arch=source — what vuln scanners match.
//
// SourceName/SourceVersion fall back to the binary name/version for packages
// that have no distinct source.
func debPURLs(p *model.Package, distro, codename string) {
	p.BomRef = purl.Deb(distro, p.Name, p.Version, p.Architecture, codename)

	name := p.SourceName
	if name == "" {
		name = p.Name
	}
	ver := p.SourceVersion
	if ver == "" {
		ver = p.Version
	}
	p.PURL = purl.Deb(distro, name, ver, "source", codename)
}

func buildDpkgFormat() string {
	var b strings.Builder
	for _, f := range dpkgFields {
		b.WriteString(f.key)
		b.WriteByte('=')
		b.WriteString(f.expr)
		b.WriteByte('\n')
	}
	b.WriteString(dpkgRecordSep)
	b.WriteByte('\n')
	return b.String()
}

// parseDpkgRecord turns one record block into a key→value map. Continuation
// lines (those not starting with a known key=) are appended to the current
// field — matches Python's behaviour for multi-line descriptions.
func parseDpkgRecord(block string) map[string]string {
	rec := make(map[string]string, len(dpkgFields))
	var currentKey string
	var currentLines []string

	flush := func() {
		if currentKey != "" {
			rec[currentKey] = strings.TrimSpace(strings.Join(currentLines, "\n"))
		}
	}

	for _, line := range strings.Split(block, "\n") {
		matched := ""
		for _, f := range dpkgFields {
			if strings.HasPrefix(line, f.key+"=") {
				matched = f.key
				break
			}
		}
		if matched != "" {
			flush()
			currentKey = matched
			currentLines = []string{line[len(matched)+1:]}
		} else if currentKey != "" {
			currentLines = append(currentLines, line)
		}
	}
	flush()
	return rec
}

func toPackage(r map[string]string) *model.Package {
	// dpkg renders Multi-Arch packages as "name:arch" in ${binary:Package}.
	// Package names never contain a colon, so strip the arch qualifier to get
	// the bare name — the architecture is captured separately (and lands in the
	// PURL `arch=` qualifier). This also keeps dependency-graph keys consistent
	// with normalizeDepName, which already strips ":arch" from dependency tokens.
	name, _, _ := strings.Cut(r["package"], ":")
	return &model.Package{
		Name:          name,
		Version:       r["version"],
		Architecture:  r["architecture"],
		Source:        r["source"],
		SourceName:    r["source_package"],
		SourceVersion: r["source_version"],
		Section:       r["section"],
		Priority:      r["priority"],
		InstalledSize: r["installed_size"],
		Maintainer:    r["maintainer"],
		Homepage:      r["homepage"],
		Origin:        r["origin"],
		Bugs:          r["bugs"],
		Essential:     r["essential"],
		MultiArch:     r["multi_arch"],
		Depends:       r["depends"],
		PreDepends:    r["pre_depends"],
		Provides:      r["provides"],
		Description:   r["description"],
		Filename:      r["filename"],
		Size:          r["size"],
		MD5:           r["md5sum"],
		SHA256:        r["sha256"],
	}
}
