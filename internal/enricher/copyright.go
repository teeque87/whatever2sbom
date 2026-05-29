package enricher

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"whatever2sbom/internal/model"
)

const copyrightBase = "/usr/share/doc"

// debianToSPDX maps the most common Debian short license names → SPDX
// identifiers. Names not in this map are passed through unchanged.
var debianToSPDX = map[string]string{
	"GPL-1":             "GPL-1.0-only",
	"GPL-1+":            "GPL-1.0-or-later",
	"GPL-2":             "GPL-2.0-only",
	"GPL-2+":            "GPL-2.0-or-later",
	"GPL-2.0-only":      "GPL-2.0-only",
	"GPL-2.0-or-later":  "GPL-2.0-or-later",
	"GPL-3":             "GPL-3.0-only",
	"GPL-3+":            "GPL-3.0-or-later",
	"GPL-3.0-only":      "GPL-3.0-only",
	"GPL-3.0-or-later":  "GPL-3.0-or-later",
	"LGPL-2":            "LGPL-2.0-only",
	"LGPL-2+":           "LGPL-2.0-or-later",
	"LGPL-2.1":          "LGPL-2.1-only",
	"LGPL-2.1+":         "LGPL-2.1-or-later",
	"LGPL-3":            "LGPL-3.0-only",
	"LGPL-3+":           "LGPL-3.0-or-later",
	"AGPL-3":            "AGPL-3.0-only",
	"AGPL-3+":           "AGPL-3.0-or-later",
	"AGPL-3.0-only":     "AGPL-3.0-only",
	"AGPL-3.0-or-later": "AGPL-3.0-or-later",
	"Apache-2":          "Apache-2.0",
	"Apache-2.0":        "Apache-2.0",
	"MIT":               "MIT",
	"ISC":               "ISC",
	"BSD-2-clause":      "BSD-2-Clause",
	"BSD-3-clause":      "BSD-3-Clause",
	"BSD-4-clause":      "BSD-4-Clause",
	"MPL-1.1":           "MPL-1.1",
	"MPL-2":             "MPL-2.0",
	"MPL-2.0":           "MPL-2.0",
	"Artistic":          "Artistic-1.0",
	"Artistic-1.0":      "Artistic-1.0",
	"Artistic-2.0":      "Artistic-2.0",
	"CC0-1.0":           "CC0-1.0",
	"CC-BY-4.0":         "CC-BY-4.0",
	"CC-BY-SA-4.0":      "CC-BY-SA-4.0",
	"Unlicense":         "Unlicense",
	"WTFPL":             "WTFPL",
	"Zlib":              "Zlib",
	"PSF-2":             "PSF-2.0",
	"PSF-2.0":           "PSF-2.0",
}

// Copyright reads /usr/share/doc/<pkg>/copyright in parallel and populates
// Package.Licenses from any DEP-5 machine-readable header.
type Copyright struct {
	// Workers caps the number of concurrent file reads. Zero → runtime.NumCPU().
	Workers int
}

// NewCopyright returns the enricher with a sensible default worker count.
func NewCopyright() *Copyright { return &Copyright{Workers: runtime.NumCPU()} }

// Name implements Enricher.
func (Copyright) Name() string { return "copyright" }

// Enrich reads each package's copyright file concurrently. Files that don't
// follow DEP-5 (free-form, missing, unreadable) silently contribute nothing.
func (e *Copyright) Enrich(pkgs []*model.Package) ([]*model.Package, error) {
	workers := e.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	var found atomic.Int64
	jobs := make(chan *model.Package)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				if lic := readLicenses(pkg.Name); len(lic) > 0 {
					pkg.Licenses = lic
					found.Add(1)
				}
			}
		}()
	}

	for _, p := range pkgs {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	slog.Info("copyright: resolved licenses",
		"found", found.Load(),
		"total", len(pkgs),
	)
	return pkgs, nil
}

// readLicenses returns the SPDX-mapped license names found in one package's
// copyright file, or an empty slice if the file is missing or not DEP-5.
func readLicenses(pkgName string) []string {
	path := filepath.Join(copyrightBase, pkgName, "copyright")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)

	// DEP-5 files start with a Format: header.
	first := strings.TrimLeft(content, " \t\r\n")
	head := content
	if len(head) > 512 {
		head = head[:512]
	}
	if !strings.HasPrefix(first, "Format:") &&
		!strings.Contains(head, "Format: https://www.debian.org") {
		return nil
	}

	names := parseDEP5(content)
	out := make([]string, len(names))
	for i, n := range names {
		if spdx, ok := debianToSPDX[n]; ok {
			out[i] = spdx
		} else {
			out[i] = n
		}
	}
	return out
}

// parseDEP5 returns the deduplicated short-name license tokens found in a
// DEP-5 copyright file. The Files: * stanza, if present, is sorted first so
// the wildcard license comes before subdir-specific overrides.
func parseDEP5(content string) []string {
	var stanzas []map[string]string
	current := make(map[string]string)
	currentField := ""
	var currentValue []string

	flushField := func() {
		if currentField != "" {
			current[currentField] = strings.TrimSpace(strings.Join(currentValue, " "))
		}
	}
	flushStanza := func() {
		flushField()
		if len(current) > 0 {
			stanzas = append(stanzas, current)
			current = make(map[string]string)
		}
		currentField = ""
		currentValue = nil
	}

	for _, line := range strings.Split(content, "\n") {
		// Strip trailing \r from CRLF files.
		line = strings.TrimRight(line, "\r")

		if line == "" || line == "." {
			flushStanza()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			stripped := strings.TrimSpace(line)
			if stripped != "" && stripped != "." {
				currentValue = append(currentValue, stripped)
			}
			continue
		}
		if strings.Contains(line, ":") {
			flushField()
			key, value, _ := strings.Cut(line, ":")
			currentField = strings.ToLower(strings.TrimSpace(key))
			currentValue = []string{strings.TrimSpace(value)}
		}
	}
	flushStanza()

	seen := make(map[string]bool)
	var out []string

	collect := func(stanza map[string]string) {
		raw := stanza["license"]
		if raw == "" {
			return
		}
		short := strings.TrimRight(strings.Fields(raw)[0], ";")
		short = strings.TrimSpace(short)
		if short != "" && !seen[short] {
			seen[short] = true
			out = append(out, short)
		}
	}

	// Wildcard stanza first, then everything else — deterministic ordering.
	for _, st := range stanzas {
		if strings.TrimSpace(st["files"]) == "*" {
			collect(st)
		}
	}
	for _, st := range stanzas {
		if strings.TrimSpace(st["files"]) != "*" {
			collect(st)
		}
	}
	return out
}
