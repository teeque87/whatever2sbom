package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode"
)

// compactHandler is a minimal slog.Handler for human-readable CLI output.
// Format: "Message  key=value  key=value\n"
// INFO entries have no prefix; WARN gets "Warning: "; ERROR gets "Error: ".
// Timestamps are never written.
type compactHandler struct {
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
}

func newCompactHandler(w io.Writer, level slog.Level) *compactHandler {
	return &compactHandler{w: w, level: level}
}

func (h *compactHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *compactHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder

	// Collect all attrs (handler-level first, then record-level).
	var attrs []slog.Attr
	attrs = append(attrs, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	// If the first attr is "→", render as "Msg → val" and stop.
	if len(attrs) > 0 && attrs[0].Key == "→" {
		sb.WriteString(capitalize(r.Message))
		sb.WriteString(" → ")
		sb.WriteString(fmt.Sprintf("%v", attrs[0].Value.Any()))
		sb.WriteByte('\n')
		_, err := fmt.Fprint(h.w, sb.String())
		return err
	}

	// Messages that already start with spaces are indented detail lines — print as-is.
	if strings.HasPrefix(r.Message, "  ") {
		switch {
		case r.Level >= slog.LevelError:
			sb.WriteString("  Error: ")
			sb.WriteString(strings.TrimLeft(r.Message, " "))
		case r.Level >= slog.LevelWarn:
			sb.WriteString("  Warning: ")
			sb.WriteString(strings.TrimLeft(r.Message, " "))
		default:
			sb.WriteString(r.Message)
		}
		sb.WriteByte('\n')
		_, err := fmt.Fprint(h.w, sb.String())
		return err
	}

	// Default: level prefix for non-INFO, capitalized message, then key=value attrs.
	switch {
	case r.Level >= slog.LevelError:
		sb.WriteString("Error: ")
	case r.Level >= slog.LevelWarn:
		sb.WriteString("Warning: ")
	}
	sb.WriteString(capitalize(r.Message))
	for _, a := range attrs {
		writeAttr(&sb, a)
	}
	sb.WriteByte('\n')
	_, err := fmt.Fprint(h.w, sb.String())
	return err
}

func (h *compactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := &compactHandler{w: h.w, level: h.level}
	n.attrs = append(n.attrs, h.attrs...)
	n.attrs = append(n.attrs, attrs...)
	return n
}

func (h *compactHandler) WithGroup(string) slog.Handler {
	return h // groups unused in this project
}

func writeAttr(sb *strings.Builder, a slog.Attr) {
	sb.WriteString("  ")
	sb.WriteString(a.Key)
	sb.WriteByte('=')
	sb.WriteString(fmt.Sprintf("%v", a.Value.Any()))
}

// capitalize uppercases the first Unicode letter of s, preserving the rest.
// "dpkg: collected packages" → "Dpkg: collected packages"
// "schema validation passed" → "Schema validation passed"
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
