package enricher

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"whatever2sbom/internal/model"
)

const aptCacheBatchSize = 100

// aptWanted maps lowercase apt-cache field names → the model field we populate.
var aptWanted = map[string]string{
	"package":  "package",
	"version":  "version",
	"sha256":   "sha256",
	"sha1":     "sha1",
	"sha512":   "sha512",
	"md5sum":   "md5sum",
	"size":     "size",
	"filename": "filename",
}

// AptCache fills hashes, size, and pool filename from `apt-cache show`.
type AptCache struct{}

// NewAptCache returns the enricher.
func NewAptCache() *AptCache { return &AptCache{} }

// Name implements Enricher.
func (AptCache) Name() string { return "apt-cache" }

// Enrich looks up every package's stanza in apt-cache and copies hash/size/filename
// fields into the matching model.Package. Apt-cache is invoked in batches of
// aptCacheBatchSize names to keep argv reasonable.
func (e *AptCache) Enrich(pkgs []*model.Package) ([]*model.Package, error) {
	slog.Info(fmt.Sprintf("  fetching metadata for %d packages", len(pkgs)))
	names := make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i] = p.Name
	}

	index, err := fetchAptCache(names)
	if err != nil {
		slog.Warn(fmt.Sprintf("  skipping apt-cache: %v", err))
		return pkgs, nil
	}

	hits := 0
	for _, pkg := range pkgs {
		stanza, ok := index[aptKey{pkg.Name, pkg.Version}]
		if !ok {
			continue
		}
		hits++
		if v := stanza["sha256"]; v != "" {
			pkg.SHA256 = v
		}
		if v := stanza["sha1"]; v != "" {
			pkg.SHA1 = v
		}
		if v := stanza["sha512"]; v != "" {
			pkg.SHA512 = v
		}
		if v := stanza["md5sum"]; v != "" {
			pkg.MD5 = v
		}
		if v := stanza["size"]; v != "" {
			pkg.Size = v
		}
		if v := stanza["filename"]; v != "" {
			pkg.Filename = v
		}
	}

	slog.Info(fmt.Sprintf("  ← %d / %d packages matched", hits, len(pkgs)))
	return pkgs, nil
}

type aptKey struct{ name, version string }

func fetchAptCache(names []string) (map[aptKey]map[string]string, error) {
	out := make(map[aptKey]map[string]string)
	for i := 0; i < len(names); i += aptCacheBatchSize {
		end := i + aptCacheBatchSize
		if end > len(names) {
			end = len(names)
		}
		batch := names[i:end]

		args := append([]string{"show", "--no-all-versions=false"}, batch...)
		cmd := exec.Command("apt-cache", args...)
		stdout, err := cmd.Output()
		if err != nil {
			// First batch failing with "not found" → abort whole enrichment.
			var exErr *exec.Error
			if errors.As(err, &exErr) && i == 0 {
				return nil, exErr
			}
			// Otherwise keep going — apt-cache returns non-zero when some
			// names are unknown, which is fine.
		}

		for _, stanza := range parseAptStanzas(string(stdout)) {
			name := stanza["package"]
			version := stanza["version"]
			if name != "" && version != "" {
				out[aptKey{name, version}] = stanza
			}
		}
	}
	return out, nil
}

// parseAptStanzas splits an apt-cache show output into one map per package
// stanza. Continuation lines (those starting with whitespace) are ignored —
// we only need top-level fields.
func parseAptStanzas(raw string) []map[string]string {
	var stanzas []map[string]string
	current := make(map[string]string)

	flush := func() {
		if len(current) > 0 {
			stanzas = append(stanzas, current)
			current = make(map[string]string)
		}
	}

	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(key))
		if mapped, ok := aptWanted[k]; ok {
			current[mapped] = strings.TrimSpace(value)
		}
	}
	flush()
	return stanzas
}
