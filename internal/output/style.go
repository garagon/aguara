package output

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Style renders Aguara's shared terminal vocabulary: one palette, one
// set of severity icons, one section-header shape across every command
// (scan, check, audit, explain, clean). NoColor strips ANSI codes but
// keeps the unicode layout intact.
type Style struct {
	NoColor bool
}

// NewStyle returns a Style honoring the resolved no-color mode.
func NewStyle(noColor bool) Style {
	return Style{NoColor: noColor}
}

func (s Style) paint(code, text string) string {
	if s.NoColor || text == "" {
		return text
	}
	return code + text + reset
}

func (s Style) Bold(t string) string      { return s.paint(bold, t) }
func (s Style) Dim(t string) string       { return s.paint(dim, t) }
func (s Style) Red(t string) string       { return s.paint(red, t) }
func (s Style) RedBold(t string) string   { return s.paint(red+bold, t) }
func (s Style) Green(t string) string     { return s.paint(green, t) }
func (s Style) Yellow(t string) string    { return s.paint(yellow, t) }
func (s Style) Blue(t string) string      { return s.paint(blue, t) }
func (s Style) Cyan(t string) string      { return s.paint(cyan, t) }
func (s Style) Underline(t string) string { return s.paint(bold+underline, t) }

// OK renders the shared clean-state line: a green check plus message.
func (s Style) OK(text string) string {
	return s.paint(green, "✔ "+text)
}

// SeverityIcon returns the icon scan introduced for each severity,
// keyed by canonical label so check/audit (string severities) and
// scan (typed severities) share one mapping. Check's WARNING maps to
// the MEDIUM tier.
func (s Style) SeverityIcon(label string) string {
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return s.paint(red+bold, "✖")
	case "HIGH":
		return s.paint(red, "▲")
	case "MEDIUM", "WARNING":
		return s.paint(yellow, "■")
	case "LOW":
		return s.paint(blue, "●")
	case "INFO":
		return s.paint(cyan, "○")
	default:
		return "?"
	}
}

// SeverityLabel returns the label painted in its severity color.
func (s Style) SeverityLabel(label string) string {
	return s.paint(severityCode(label), label)
}

func severityCode(label string) string {
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return red + bold
	case "HIGH":
		return red
	case "MEDIUM", "WARNING":
		return yellow
	case "LOW":
		return blue
	case "INFO":
		return cyan
	default:
		return ""
	}
}

// Cell pads or truncates text to exactly w columns -- the shape scan
// uses for aligned finding columns.
func (s Style) Cell(text string, w int) string {
	return fmt.Sprintf("%-*s", w, truncate(text, w))
}

// Separator renders a full-width dim rule line. Zero width falls back
// to the 72-column default.
func (s Style) Separator(width int) string {
	if width <= 0 {
		width = lineWidth
	}
	return s.paint(dim, strings.Repeat("─", width))
}

// SectionHeader renders the shared "── TITLE ────" shape padded to
// width (zero → 72), bold like scan's severity sections.
func (s Style) SectionHeader(title string, width int) string {
	if width <= 0 {
		width = lineWidth
	}
	prefix := "── " + title + " "
	remaining := max(width-utf8.RuneCountInString(prefix), 0)
	return s.paint(bold, prefix+strings.Repeat("─", remaining))
}
