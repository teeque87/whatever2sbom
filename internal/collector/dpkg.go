package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"whatever2sbom/internal/model"
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
}

// NewDpkg returns a collector that filters to installed packages.
func NewDpkg() *DpkgCollector { return &DpkgCollector{InstalledOnly: true} }

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

	slog.Info("dpkg: collected packages", "count", len(pkgs))
	return pkgs, nil
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
	return &model.Package{
		Name:          r["package"],
		Version:       r["version"],
		Architecture:  r["architecture"],
		Source:        r["source"],
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
