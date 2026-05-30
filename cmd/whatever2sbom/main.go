// Command whatever2sbom generates a validated CycloneDX 1.6 SBOM for a
// Debian/Ubuntu system by walking the dpkg database, enriching with
// apt-cache, and extracting licenses from /usr/share/doc/<pkg>/copyright.
//
// Output is always validated against the embedded JSON schema before being
// written; failing validation aborts the run with a non-zero exit code.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"whatever2sbom/internal/collector"
	"whatever2sbom/internal/enricher"
	"whatever2sbom/internal/formatter"
	"whatever2sbom/internal/pipeline"
	"whatever2sbom/internal/validator"
)

// Build-time identity. Override with -ldflags
//
//	"-X main.toolName=foo -X main.toolVersion=v1.2.3"
var (
	toolName    = "whatever2sbom"
	toolVersion = "0.1.0-go"
)

// stringList satisfies flag.Value for repeated flags (--author X --author Y).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// ── usage ────────────────────────────────────────────────────────────────────

const usagePrefix = `whatever2sbom — generate a validated CycloneDX SBOM.

USAGE:
  whatever2sbom --product-supplier NAME [options]

EXAMPLES:
  whatever2sbom --product-supplier "Acme GmbH"
  whatever2sbom --no-licenses --product-supplier Acme -o fast.cdx.json
  whatever2sbom \
      --product-name AcmeFW --product-version 2.4.1 --product-type firmware \
      --product-supplier "Acme GmbH" --product-supplier-url https://acme.example \
      --product-purl "pkg:generic/acme/acmefw@2.4.1" \
      --author "Jane Doe <jane@acme.example>" \
      -o acmefw.cdx.json

OPTIONS:
`

func printUsage(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, usagePrefix)
	printOptions(fs)
}

// printOptions writes the per-flag help block, replacing Go's stdlib
// `PrintDefaults` which always renders flags with a single leading dash.
// Multi-character flags get `--`, single-character flags keep `-`.
func printOptions(fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		prefix := "--"
		if len(f.Name) == 1 {
			prefix = "-"
		}
		typeName, usage := flag.UnquoteUsage(f)

		var head strings.Builder
		fmt.Fprintf(&head, "  %s%s", prefix, f.Name)
		if typeName != "" {
			fmt.Fprintf(&head, " %s", typeName)
		}

		var def string
		if !isZeroDefault(f.DefValue, typeName) {
			if typeName == "string" {
				def = fmt.Sprintf(" (default %q)", f.DefValue)
			} else {
				def = fmt.Sprintf(" (default %s)", f.DefValue)
			}
		}

		fmt.Fprintf(os.Stderr, "%s\n        %s%s\n", head.String(), usage, def)
	})
}

// isZeroDefault reports whether a flag's default is its type's zero value.
// We render the "(default ...)" suffix only when the default is non-zero,
// matching what stdlib `PrintDefaults` does.
func isZeroDefault(v, typeName string) bool {
	switch typeName {
	case "": // bool flags have no type hint
		return v == "false"
	case "string":
		return v == ""
	default:
		return v == "" || v == "0"
	}
}

func main() {
	formatter.SetToolMetadata(toolName, toolVersion)

	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	// ── global ────────────────────────────────────────────────────────────────
	system := fs.String("system", "dpkg", "What to scan. Available: dpkg")
	schema := fs.String("schema", "cyclonedx", "Output schema. Available: cyclonedx")
	specVersion := fs.String("spec-version", "1.6", "Schema spec version")
	output := fs.String("output", "", "Output file path (default: sbom_<timestamp>.cdx.json)")
	outputShort := fs.String("o", "", "Shorthand for --output")
	verbose := fs.Bool("verbose", false, "Enable debug-level logging to stderr")
	verboseShort := fs.Bool("v", false, "Shorthand for --verbose")

	// ── product metadata (BSI TR-03183) ───────────────────────────────────────
	productName := fs.String("product-name", "", "Name of the product or firmware image")
	productVersion := fs.String("product-version", "", "Version of the product")
	productType := fs.String("product-type", "firmware", "CycloneDX component type for the product")
	productSupplier := fs.String("product-supplier", "", "Supplier / vendor name (required — NTIA Supplier Name)")
	var productSupplierURLs stringList
	fs.Var(&productSupplierURLs, "product-supplier-url", "Supplier URL (may be given multiple times)")
	productPURL := fs.String("product-purl", "", "Package-URL that uniquely identifies the product")
	var authors stringList
	fs.Var(&authors, "author", "SBOM author in 'Name <email>' format (may be given multiple times)")

	// ── dpkg system options ───────────────────────────────────────────────────
	distro := fs.String("distro", "", "Override the OS distro identifier used in package PURLs")
	noAptCache := fs.Bool("no-apt-cache", false, "Skip apt-cache hash/filename enrichment")
	noLicenses := fs.Bool("no-licenses", false, "Skip license extraction from copyright files")

	fs.Usage = func() { printUsage(fs) }

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	// Reconcile short/long forms.
	if *outputShort != "" && *output == "" {
		*output = *outputShort
	}
	if *verboseShort {
		*verbose = true
	}

	// Logging — debug to stderr if --verbose, else info.
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(newCompactHandler(os.Stderr, logLevel)))

	// Required flag.
	if *productSupplier == "" {
		fmt.Fprintln(os.Stderr, "error: --product-supplier is required")
		fmt.Fprintln(os.Stderr, "run with --help for usage.")
		os.Exit(2)
	}

	// Reject unknown --system / --schema choices early.
	if *system != "dpkg" {
		fmt.Fprintf(os.Stderr, "error: unknown --system %q. Available: dpkg\n", *system)
		os.Exit(2)
	}
	if *schema != "cyclonedx" || *specVersion != "1.6" {
		fmt.Fprintf(os.Stderr,
			"error: no formatter for --schema %q --spec-version %q. Available: cyclonedx/1.6\n",
			*schema, *specVersion)
		os.Exit(2)
	}

	// ── wire pipeline ─────────────────────────────────────────────────────────
	col := collector.NewDpkg(*distro)

	var ers []enricher.Enricher
	if !*noAptCache {
		ers = append(ers, enricher.NewAptCache())
	}
	if !*noLicenses {
		ers = append(ers, enricher.NewCopyright())
	}

	prod := formatter.ProductOptions{
		Name:         *productName,
		Version:      *productVersion,
		Type:         *productType,
		Supplier:     *productSupplier,
		SupplierURLs: []string(productSupplierURLs),
		PURL:         *productPURL,
		Authors:      []string(authors),
	}
	fmtr := formatter.NewCycloneDX16(*distro, prod)

	val, err := validator.NewCycloneDXSchema()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pl := pipeline.New(col, ers, fmtr, []validator.Validator{val})

	bom, err := pl.Run()
	if err != nil {
		var ve *pipeline.ValidationError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "Schema validation failed (%d error(s)):\n", len(ve.Errors))
			for _, e := range ve.Errors {
				fmt.Fprintf(os.Stderr, "  %s\n", e)
			}
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// ── write output ──────────────────────────────────────────────────────────
	outPath := *output
	if outPath == "" {
		outPath = defaultFilename(fmtr.OutputExtension())
	}

	// encoding/json HTML-escapes &, <, > by default (`&` etc.) — useful
	// when embedding JSON in HTML, ugly and wrong for a CLI that writes to
	// disk for downstream SBOM consumers. PURL qualifiers like `&distro=...`
	// must survive verbatim. Use a streaming encoder so we can disable it.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bom); err != nil {
		fmt.Fprintf(os.Stderr, "Error: encoding BOM: %v\n", err)
		os.Exit(1)
	}
	// Encoder.Encode adds a trailing newline; match Python's json.dumps()
	// which doesn't, so the two implementations produce identical bytes.
	raw := bytes.TrimRight(buf.Bytes(), "\n")
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: writing %s: %v\n", outPath, err)
		os.Exit(1)
	}

	// ── summary ───────────────────────────────────────────────────────────────
	fmt.Printf("SBOM written → %s\n", outPath)
	fmt.Printf("  system          : %s\n", col.Name())
	fmt.Printf("  schema          : %s %s\n", fmtr.SchemaName(), fmtr.SpecVersion())
	printSummary(bom)
}

func defaultFilename(ext string) string {
	return fmt.Sprintf("sbom_%s.%s", time.Now().Format("20060102_150405"), ext)
}

// printSummary fishes the metadata.properties out of the BOM for the
// post-run coverage report. The BOM is the formatter's internal type, so
// we round-trip through JSON to read it generically.
func printSummary(bom any) {
	raw, err := json.Marshal(bom)
	if err != nil {
		return
	}
	var doc struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	props := make(map[string]string, len(doc.Metadata.Properties))
	for _, p := range doc.Metadata.Properties {
		props[p.Name] = p.Value
	}
	for _, pair := range []struct{ key, label string }{
		{"sbom:total-components", "total components"},
		{"sbom:hash-coverage-pct", "hash coverage"},
		{"sbom:license-coverage-pct", "license coverage"},
	} {
		if v, ok := props[pair.key]; ok {
			fmt.Printf("  %-16s: %s\n", pair.label, v)
		}
	}
}
