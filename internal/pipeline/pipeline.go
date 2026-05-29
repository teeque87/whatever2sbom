// Package pipeline runs collect → enrich → format → validate as one unit.
package pipeline

import (
	"fmt"
	"log/slog"

	"whatever2sbom/internal/collector"
	"whatever2sbom/internal/enricher"
	"whatever2sbom/internal/formatter"
	"whatever2sbom/internal/validator"
)

// ValidationError carries the per-violation messages produced by a Validator.
type ValidationError struct {
	Errors []string
}

// Error implements error.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%d validation error(s)", len(e.Errors))
}

// Pipeline wires the stages together. Construct it via New and call Run once.
type Pipeline struct {
	Collector  collector.Collector
	Enrichers  []enricher.Enricher
	Formatter  formatter.Formatter
	Validators []validator.Validator
}

// New returns a configured pipeline. All stages run unconditionally.
func New(
	c collector.Collector,
	es []enricher.Enricher,
	f formatter.Formatter,
	vs []validator.Validator,
) *Pipeline {
	return &Pipeline{Collector: c, Enrichers: es, Formatter: f, Validators: vs}
}

// Run executes the pipeline. Returns the formatted BOM and any error.
// Validation failures return *ValidationError so the caller can render
// per-violation messages.
func (p *Pipeline) Run() (any, error) {
	slog.Info("collecting", "source", p.Collector.Name())
	pkgs, err := p.Collector.Collect()
	if err != nil {
		return nil, err
	}
	slog.Info("collected", "packages", len(pkgs))

	for _, e := range p.Enrichers {
		slog.Info("enriching", "via", e.Name())
		pkgs, err = e.Enrich(pkgs)
		if err != nil {
			return nil, err
		}
	}

	slog.Info("formatting", "via", p.Formatter.Name())
	bom, err := p.Formatter.Format(pkgs)
	if err != nil {
		return nil, err
	}

	for _, v := range p.Validators {
		slog.Info("validating", "via", v.Name())
		if errs := v.Validate(bom); len(errs) > 0 {
			return nil, &ValidationError{Errors: errs}
		}
	}

	return bom, nil
}
