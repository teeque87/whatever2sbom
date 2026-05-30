package formatter

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatever2sbom/internal/model"
	"whatever2sbom/internal/osinfo"
)

// Tool identity is injected at build time via main.SetToolMetadata so the
// formatter doesn't depend on the cmd package.
var (
	toolName    = "whatever2sbom"
	toolVersion = "0.0.0+dev"
)

// SetToolMetadata is called once at startup with the binary's name/version.
func SetToolMetadata(name, version string) {
	if name != "" {
		toolName = name
	}
	if version != "" {
		toolVersion = version
	}
}

var (
	librarySections  = stringSet("libs", "libdevel", "python", "perl", "ruby", "java", "javascript", "lisp", "ocaml", "haskell")
	firmwareSections = stringSet("firmware")
	osSections       = stringSet("kernel")

	// Match "Name <email>".
	maintainerRE = regexp.MustCompile(`^(.*?)\s*<([^>]+)>`)
	// Strip "(>= 1.2)" version constraints.
	versionConstraintRE = regexp.MustCompile(`\(.*?\)`)
	// Strip "[amd64 i386]" architecture filters.
	archFilterRE = regexp.MustCompile(`\[.*?\]`)
)

func stringSet(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// CycloneDX16 produces a CycloneDX 1.6 JSON BOM.
type CycloneDX16 struct {
	Distro  string
	Product ProductOptions
}

// NewCycloneDX16 returns a configured formatter.
func NewCycloneDX16(distro string, prod ProductOptions) *CycloneDX16 {
	return &CycloneDX16{Distro: distro, Product: prod}
}

// Name implements Formatter.
func (f *CycloneDX16) Name() string { return "cyclonedx-1.6" }

// SchemaName implements Formatter.
func (f *CycloneDX16) SchemaName() string { return "cyclonedx" }

// SpecVersion implements Formatter.
func (f *CycloneDX16) SpecVersion() string { return "1.6" }

// OutputExtension implements Formatter.
func (f *CycloneDX16) OutputExtension() string { return "cdx.json" }

// ── JSON output types ────────────────────────────────────────────────────────

type bom struct {
	BomFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     metadata     `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      tools      `json:"tools"`
	Component  any        `json:"component"`
	Properties []property `json:"properties"`
	Supplier   *supplier  `json:"supplier,omitempty"`
	Authors    []author   `json:"authors,omitempty"`
}

type tools struct {
	Components []toolComponent `json:"components"`
}

type toolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type component struct {
	Type         string        `json:"type"`
	BomRef       string        `json:"bom-ref"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Purl         string        `json:"purl"`
	Scope        string        `json:"scope"`
	Description  string        `json:"description,omitempty"`
	Supplier     *supplier     `json:"supplier,omitempty"`
	Licenses     []licenseRef  `json:"licenses,omitempty"`
	Hashes       []hash        `json:"hashes,omitempty"`
	ExternalRefs []externalRef `json:"externalReferences,omitempty"`
	Properties   []property    `json:"properties,omitempty"`
}

type supplier struct {
	Name    string    `json:"name"`
	URL     []string  `json:"url,omitempty"`
	Contact []contact `json:"contact,omitempty"`
}

type contact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type licenseRef struct {
	License licenseInner `json:"license"`
}

type licenseInner struct {
	Name string `json:"name"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type externalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type author struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// productComponent is the typed metadata.component when product flags are set.
type productComponent struct {
	Type     string    `json:"type"`
	BomRef   string    `json:"bom-ref"`
	Name     string    `json:"name"`
	Version  string    `json:"version,omitempty"`
	Purl     string    `json:"purl,omitempty"`
	Supplier *supplier `json:"supplier,omitempty"`
}

// osComponent is the metadata.component when no product flags are set.
type osComponent struct {
	Type         string        `json:"type"`
	BomRef       string        `json:"bom-ref"`
	Name         string        `json:"name"`
	Version      string        `json:"version,omitempty"`
	Description  string        `json:"description,omitempty"`
	ExternalRefs []externalRef `json:"externalReferences,omitempty"`
}

// ── core ─────────────────────────────────────────────────────────────────────

// Format builds the BOM. Returns any so the validator/encoder stages can
// process it without depending on these unexported types.
func (f *CycloneDX16) Format(pkgs []*model.Package) (any, error) {
	osInfo := osinfo.Get()
	distro := f.Distro
	if distro == "" {
		if id := osInfo["id"]; id != "" {
			distro = id
		} else {
			distro = "debian"
		}
	}
	// name → bom-ref index, plus the reverse list of refs (used for the
	// root "dependsOn" so the order matches the components array). PURLs are
	// built by the collector; the formatter just consumes them.
	nameToRef := make(map[string]string, len(pkgs))
	pkgRefs := make([]string, len(pkgs))
	for i, p := range pkgs {
		nameToRef[p.Name] = p.BomRef
		pkgRefs[i] = p.BomRef
	}
	providesMap := buildProvidesMap(pkgs, nameToRef)

	components := make([]component, len(pkgs))
	for i, p := range pkgs {
		components[i] = f.buildComponent(p)
	}

	deps := f.buildDependencies(pkgs, nameToRef, providesMap)

	rootRef := f.rootBomRef()
	// Single dep-tree root pointing at every package — inserted first.
	deps = append([]dependency{{Ref: rootRef, DependsOn: pkgRefs}}, deps...)

	out := bom{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid.NewString(),
		Version:      1,
		Metadata:     f.buildMetadata(osInfo, distro, components),
		Components:   components,
		Dependencies: deps,
	}

	return out, nil
}

// ── dep-string helpers ───────────────────────────────────────────────────────

// normalizeDepName strips version constraints, arch filters, and arch
// qualifiers from one dependency token.
func normalizeDepName(token string) string {
	token = versionConstraintRE.ReplaceAllString(token, "")
	token = archFilterRE.ReplaceAllString(token, "")
	if i := strings.IndexByte(token, ':'); i >= 0 {
		token = token[:i]
	}
	return strings.TrimSpace(token)
}

// buildProvidesMap returns virtualName → bom-ref by scanning every package's
// Provides field.
func buildProvidesMap(pkgs []*model.Package, nameToRef map[string]string) map[string]string {
	out := make(map[string]string)
	for _, p := range pkgs {
		if p.Provides == "" {
			continue
		}
		ref, ok := nameToRef[p.Name]
		if !ok {
			continue
		}
		for _, entry := range strings.Split(p.Provides, ",") {
			v := normalizeDepName(entry)
			if v == "" {
				continue
			}
			if _, exists := out[v]; !exists {
				out[v] = ref
			}
		}
	}
	return out
}

// resolveDeps parses a Depends/Pre-Depends field. Comma-separated groups are
// all collected; pipe-separated alternatives keep only the first installed one.
func resolveDeps(depString string, nameToRef, providesMap map[string]string) []string {
	var out []string
	for _, group := range strings.Split(depString, ",") {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		for _, alt := range strings.Split(group, "|") {
			name := normalizeDepName(alt)
			if name == "" {
				continue
			}
			ref, ok := nameToRef[name]
			if !ok {
				ref, ok = providesMap[name]
			}
			if ok {
				out = append(out, ref)
				break // first satisfied alternative wins
			}
		}
	}
	return out
}

// ── component builders ───────────────────────────────────────────────────────

func mapType(p *model.Package) string {
	section := strings.ToLower(p.Section)
	if i := strings.LastIndexByte(section, '/'); i >= 0 {
		section = section[i+1:]
	}
	if strings.EqualFold(p.Essential, "yes") {
		return "application"
	}
	if librarySections[section] {
		return "library"
	}
	if firmwareSections[section] {
		return "firmware"
	}
	if osSections[section] {
		return "operating-system"
	}
	return "library"
}

func mapScope(p *model.Package) string {
	if strings.EqualFold(p.Essential, "yes") {
		return "required"
	}
	switch strings.ToLower(p.Priority) {
	case "required", "important":
		return "required"
	}
	return "optional"
}

func buildSupplier(maintainer string) *supplier {
	if maintainer == "" {
		return nil
	}
	if m := maintainerRE.FindStringSubmatch(strings.TrimSpace(maintainer)); m != nil {
		name := strings.TrimSpace(m[1])
		email := strings.TrimSpace(m[2])
		return &supplier{
			Name:    name,
			Contact: []contact{{Name: name, Email: email}},
		}
	}
	return &supplier{Name: strings.TrimSpace(maintainer)}
}

func buildHashes(p *model.Package) []hash {
	pairs := []struct{ value, alg string }{
		{p.SHA256, "SHA-256"},
		{p.SHA512, "SHA-512"},
		{p.SHA1, "SHA-1"},
		{p.MD5, "MD5"},
	}
	var out []hash
	for _, pair := range pairs {
		if pair.value != "" {
			out = append(out, hash{Alg: pair.alg, Content: pair.value})
		}
	}
	return out
}

func buildLicenses(p *model.Package) []licenseRef {
	if len(p.Licenses) == 0 {
		return nil
	}
	out := make([]licenseRef, len(p.Licenses))
	for i, lic := range p.Licenses {
		out[i] = licenseRef{License: licenseInner{Name: lic}}
	}
	return out
}

func buildExtRefs(p *model.Package) []externalRef {
	var out []externalRef
	if p.Homepage != "" {
		out = append(out, externalRef{Type: "website", URL: p.Homepage})
	}
	if p.Bugs != "" {
		out = append(out, externalRef{Type: "issue-tracker", URL: p.Bugs})
	}
	if p.Filename != "" {
		out = append(out, externalRef{Type: "distribution", URL: p.Filename})
	}
	return out
}

func buildProperties(p *model.Package) []property {
	pairs := []struct{ value, name string }{
		{p.Section, "dpkg:section"},
		{p.Priority, "dpkg:priority"},
		{p.InstalledSize, "dpkg:installed-size"},
		{p.Size, "dpkg:download-size"},
		{p.Source, "dpkg:source"},
		{p.SourceName, "dpkg:source-name"},
		{p.SourceVersion, "dpkg:source-version"},
		{p.Origin, "dpkg:origin"},
		{p.MultiArch, "dpkg:multi-arch"},
	}
	var out []property
	for _, pair := range pairs {
		if pair.value != "" {
			out = append(out, property{Name: pair.name, Value: pair.value})
		}
	}
	return out
}

func (f *CycloneDX16) buildComponent(p *model.Package) component {
	// PURLs come from the collector: bom-ref is the unique per-binary coordinate
	// (keeps the dependency graph intact); the matchable `purl` is the source
	// coordinate scanners key on.
	return component{
		Type:         mapType(p),
		BomRef:       p.BomRef,
		Name:         p.Name,
		Version:      p.Version,
		Purl:         p.PURL,
		Scope:        mapScope(p),
		Description:  p.Description,
		Supplier:     buildSupplier(p.Maintainer),
		Licenses:     buildLicenses(p),
		Hashes:       buildHashes(p),
		ExternalRefs: buildExtRefs(p),
		Properties:   buildProperties(p),
	}
}

// ── dependencies ─────────────────────────────────────────────────────────────

func (f *CycloneDX16) buildDependencies(
	pkgs []*model.Package,
	nameToRef, providesMap map[string]string,
) []dependency {
	out := make([]dependency, 0, len(pkgs))
	for _, p := range pkgs {
		seen := make(map[string]bool)
		direct := []string{}
		selfRef := nameToRef[p.Name]
		for _, field := range []string{p.PreDepends, p.Depends} {
			if field == "" {
				continue
			}
			for _, ref := range resolveDeps(field, nameToRef, providesMap) {
				if ref != selfRef && !seen[ref] {
					seen[ref] = true
					direct = append(direct, ref)
				}
			}
		}
		out = append(out, dependency{Ref: selfRef, DependsOn: direct})
	}
	return out
}

// ── metadata ─────────────────────────────────────────────────────────────────

func (f *CycloneDX16) rootBomRef() string {
	if f.Product.PURL != "" {
		return f.Product.PURL
	}
	if f.Product.Name != "" {
		return "product:" + f.Product.Name
	}
	return "os-component"
}

func (f *CycloneDX16) buildMetadata(osInfo map[string]string, distro string, components []component) metadata {
	total := len(components)
	hashCov := 0
	licCov := 0
	for _, c := range components {
		if len(c.Hashes) > 0 {
			hashCov++
		}
		if len(c.Licenses) > 0 {
			licCov++
		}
	}

	hashPct := "0%"
	licPct := "0%"
	if total > 0 {
		hashPct = fmt.Sprintf("%.1f%%", float64(hashCov)/float64(total)*100)
		licPct = fmt.Sprintf("%.1f%%", float64(licCov)/float64(total)*100)
	}

	md := metadata{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00"),
		Tools: tools{
			Components: []toolComponent{
				{Type: "application", Name: toolName, Version: toolVersion},
			},
		},
		Component: f.buildMetadataComponent(osInfo, distro),
		Properties: []property{
			{Name: "sbom:total-components", Value: fmt.Sprintf("%d", total)},
			{Name: "sbom:hash-coverage", Value: fmt.Sprintf("%d", hashCov)},
			{Name: "sbom:hash-coverage-pct", Value: hashPct},
			{Name: "sbom:license-coverage", Value: fmt.Sprintf("%d", licCov)},
			{Name: "sbom:license-coverage-pct", Value: licPct},
		},
	}

	// Top-level supplier (NTIA Supplier Name) is always emitted when
	// --product-supplier was given (it's required by the CLI).
	if f.Product.Supplier != "" {
		s := &supplier{Name: f.Product.Supplier}
		if len(f.Product.SupplierURLs) > 0 {
			s.URL = f.Product.SupplierURLs
		}
		md.Supplier = s
	}

	if authors := f.buildAuthors(); len(authors) > 0 {
		md.Authors = authors
	}

	return md
}

func (f *CycloneDX16) buildMetadataComponent(osInfo map[string]string, distro string) any {
	if f.Product.Name != "" {
		ref := f.Product.PURL
		if ref == "" {
			ref = "product:" + f.Product.Name
		}
		c := productComponent{
			Type:    f.Product.Type,
			BomRef:  ref,
			Name:    f.Product.Name,
			Version: f.Product.Version,
			Purl:    f.Product.PURL,
		}
		if f.Product.Supplier != "" {
			s := &supplier{Name: f.Product.Supplier}
			if len(f.Product.SupplierURLs) > 0 {
				s.URL = f.Product.SupplierURLs
			}
			c.Supplier = s
		}
		return c
	}

	// Fallback: describe the OS that was scanned.
	name := osInfo["id"]
	if name == "" {
		name = distro
	}
	oc := osComponent{
		Type:        "operating-system",
		BomRef:      "os-component",
		Name:        name,
		Version:     osInfo["version_id"],
		Description: osInfo["pretty_name"],
	}
	if url := osInfo["home_url"]; url != "" {
		oc.ExternalRefs = []externalRef{{Type: "website", URL: url}}
	}
	return oc
}

func (f *CycloneDX16) buildAuthors() []author {
	var out []author
	for _, entry := range f.Product.Authors {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if m := maintainerRE.FindStringSubmatch(entry); m != nil {
			out = append(out, author{
				Name:  strings.TrimSpace(m[1]),
				Email: strings.TrimSpace(m[2]),
			})
		} else {
			out = append(out, author{Name: entry})
		}
	}
	return out
}
