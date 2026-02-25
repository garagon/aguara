package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/scanner"
)

// ANSI color codes
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	underline = "\033[4m"
	red       = "\033[31m"
	yellow    = "\033[33m"
	blue      = "\033[34m"
	magenta   = "\033[35m"
	cyan      = "\033[36m"
	white     = "\033[37m"
	bgRed     = "\033[41m"
	bgYellow  = "\033[43m"
	bgBlue    = "\033[44m"
)

const (
	barWidth     = 40
	lineWidth    = 72
	ruleIDWidth  = 24
	nameWidth    = 36
	previewWidth = 60
)

// TerminalFormatter outputs findings in a triage-optimized format.
type TerminalFormatter struct {
	NoColor bool
	Verbose bool
}

func (f *TerminalFormatter) color(code, text string) string {
	if f.NoColor {
		return text
	}
	return code + text + reset
}

func (f *TerminalFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	if f.NoColor {
		if os.Getenv("NO_COLOR") != "" {
			f.NoColor = true
		}
	}

	f.printHeader(w, result)

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "\n  %s No security issues found.\n", f.color(cyan, "\u2714"))
	} else {
		counts := f.countBySeverity(result.Findings)
		f.printDashboard(w, counts)

		severities := []scanner.Severity{
			scanner.SeverityCritical,
			scanner.SeverityHigh,
			scanner.SeverityMedium,
			scanner.SeverityLow,
			scanner.SeverityInfo,
		}
		for _, sev := range severities {
			filtered := filterBySeverity(result.Findings, sev)
			if len(filtered) > 0 {
				f.printSeveritySection(w, sev, filtered)
			}
		}

		f.printTopFiles(w, result.Findings)
	}

	f.printFooter(w, result)
	return nil
}

func (f *TerminalFormatter) separator() string {
	return strings.Repeat("\u2500", lineWidth)
}

func (f *TerminalFormatter) sectionHeader(title string) string {
	prefix := "\u2500\u2500 " + title + " "
	displayLen := utf8.RuneCountInString(prefix)
	remaining := max(lineWidth-displayLen, 0)
	return prefix + strings.Repeat("\u2500", remaining)
}

func (f *TerminalFormatter) printHeader(w io.Writer, result *scanner.ScanResult) {
	sep := f.separator()
	fmt.Fprintf(w, "\n%s\n", f.color(dim, sep))
	fmt.Fprintf(w, "  %s\n", f.color(bold, "AGUARA SCAN RESULTS"))

	parts := []string{}
	if result.Target != "" {
		parts = append(parts, fmt.Sprintf("Target: %s", result.Target))
	}
	parts = append(parts, fmt.Sprintf("%d files", result.FilesScanned))
	parts = append(parts, fmt.Sprintf("%d rules", result.RulesLoaded))
	if result.Duration > 0 {
		parts = append(parts, fmt.Sprintf("%.2fs", result.Duration.Seconds()))
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(parts, "  \u00b7  "))
	fmt.Fprintf(w, "%s\n", f.color(dim, sep))
}

func (f *TerminalFormatter) printDashboard(w io.Writer, counts map[scanner.Severity]int) {
	max := 0
	for _, c := range counts {
		if c > max {
			max = c
		}
	}
	if max == 0 {
		return
	}

	fmt.Fprintln(w)
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}
	for _, sev := range severities {
		c := counts[sev]
		if c == 0 {
			continue
		}
		label := fmt.Sprintf("  %-10s", sev.String())
		bar := f.renderBar(c, max, barWidth, sev)
		fmt.Fprintf(w, "%s %s %4d\n", f.color(bold, label), bar, c)
	}

	total := 0
	for _, c := range counts {
		total += c
	}
	fmt.Fprintf(w, "\n  %s\n", f.color(bold, fmt.Sprintf("%d findings", total)))
}

func (f *TerminalFormatter) printSeveritySection(w io.Writer, sev scanner.Severity, findings []scanner.Finding) {
	count := len(findings)
	title := fmt.Sprintf("%s (%d)", sev.String(), count)
	header := f.sectionHeader(title)
	fmt.Fprintf(w, "\n%s\n", f.color(bold, header))

	grouped := groupByFile(findings)
	for _, group := range grouped {
		fmt.Fprintf(w, "\n  %s\n", f.color(bold+underline, group.filePath))
		for _, finding := range group.findings {
			if sev == scanner.SeverityCritical {
				f.printFindingExpanded(w, finding)
			} else {
				f.printFindingCompact(w, finding)
			}
		}
	}
}

func (f *TerminalFormatter) printFindingExpanded(w io.Writer, finding scanner.Finding) {
	icon := f.severityIcon(finding.Severity)
	ruleID := fmt.Sprintf("%-*s", ruleIDWidth, finding.RuleID)
	name := truncate(finding.RuleName, nameWidth)
	namePadded := fmt.Sprintf("%-*s", nameWidth, name)
	lineStr := fmt.Sprintf("%s:%d", finding.FilePath, finding.Line)
	if finding.InCodeBlock {
		lineStr += " " + f.color(dim, "[code]")
	}

	fmt.Fprintf(w, "\n    %s %s %s %s\n",
		icon,
		f.color(bold, ruleID),
		namePadded,
		f.color(cyan, lineStr),
	)

	if finding.MatchedText != "" {
		preview := truncate(finding.MatchedText, previewWidth)
		fmt.Fprintf(w, "      %s %s\n", f.color(dim, "\u2502"), f.color(dim, preview))
	}
	if f.Verbose && finding.Description != "" {
		fmt.Fprintf(w, "      %s %s\n", f.color(dim, "\u2502"), f.color(yellow, finding.Description))
	}
}

func (f *TerminalFormatter) printFindingCompact(w io.Writer, finding scanner.Finding) {
	icon := f.severityIcon(finding.Severity)
	ruleID := fmt.Sprintf("%-*s", ruleIDWidth, finding.RuleID)
	name := truncate(finding.RuleName, nameWidth)
	namePadded := fmt.Sprintf("%-*s", nameWidth, name)
	lineStr := fmt.Sprintf("%s:%d", finding.FilePath, finding.Line)
	if finding.InCodeBlock {
		lineStr += " " + f.color(dim, "[code]")
	}

	fmt.Fprintf(w, "    %s %s %s %s\n",
		icon,
		f.color(bold, ruleID),
		namePadded,
		f.color(cyan, lineStr),
	)
	if f.Verbose && finding.Severity >= scanner.SeverityHigh && finding.Description != "" {
		fmt.Fprintf(w, "      %s %s\n", f.color(dim, "\u2502"), f.color(yellow, finding.Description))
	}
}

func (f *TerminalFormatter) printTopFiles(w io.Writer, findings []scanner.Finding) {
	fileCounts := map[string]int{}
	for _, finding := range findings {
		fileCounts[finding.FilePath]++
	}

	type fileCount struct {
		path  string
		count int
	}
	sorted := make([]fileCount, 0, len(fileCounts))
	for path, count := range fileCounts {
		sorted = append(sorted, fileCount{path, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].path < sorted[j].path
	})

	limit := min(len(sorted), 5)
	if limit == 0 {
		return
	}

	header := f.sectionHeader("TOP AFFECTED FILES")
	fmt.Fprintf(w, "\n%s\n\n", f.color(bold, header))

	for i := range limit {
		fmt.Fprintf(w, "  %4d  %s\n", sorted[i].count, sorted[i].path)
	}
}

func (f *TerminalFormatter) printFooter(w io.Writer, result *scanner.ScanResult) {
	sep := f.separator()
	fmt.Fprintf(w, "\n%s\n", f.color(dim, sep))

	parts := []string{
		fmt.Sprintf("%d files scanned", result.FilesScanned),
		fmt.Sprintf("%d findings", len(result.Findings)),
		fmt.Sprintf("%d rules", result.RulesLoaded),
	}
	if result.Duration > 0 {
		parts = append(parts, fmt.Sprintf("%.2fs", result.Duration.Seconds()))
	}

	fmt.Fprintf(w, "  %s\n", strings.Join(parts, " \u00b7 "))
	fmt.Fprintf(w, "%s\n", f.color(dim, sep))
}

func (f *TerminalFormatter) severityIcon(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return f.color(red+bold, "\u2716")
	case scanner.SeverityHigh:
		return f.color(red, "\u25b2")
	case scanner.SeverityMedium:
		return f.color(yellow, "\u25a0")
	case scanner.SeverityLow:
		return f.color(blue, "\u25cf")
	case scanner.SeverityInfo:
		return f.color(cyan, "\u25cb")
	default:
		return "?"
	}
}

func (f *TerminalFormatter) severityColor(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return red + bold
	case scanner.SeverityHigh:
		return red
	case scanner.SeverityMedium:
		return yellow
	case scanner.SeverityLow:
		return blue
	case scanner.SeverityInfo:
		return cyan
	default:
		return ""
	}
}

func (f *TerminalFormatter) renderBar(count, max, width int, sev scanner.Severity) string {
	if max == 0 {
		return strings.Repeat("\u2591", width)
	}
	filled := count * width / max
	if filled == 0 && count > 0 {
		filled = 1
	}
	// Always keep at least 1 empty block so bar boundary is visible
	if filled >= width {
		filled = width - 1
	}
	empty := width - filled

	filledStr := strings.Repeat("\u2588", filled)
	emptyStr := strings.Repeat("\u2591", empty)
	return f.color(f.severityColor(sev), filledStr) + f.color(dim, emptyStr)
}

func (f *TerminalFormatter) countBySeverity(findings []scanner.Finding) map[scanner.Severity]int {
	counts := map[scanner.Severity]int{}
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

func filterBySeverity(findings []scanner.Finding, sev scanner.Severity) []scanner.Finding {
	var result []scanner.Finding
	for _, f := range findings {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

type fileGroup struct {
	filePath string
	findings []scanner.Finding
}

func groupByFile(findings []scanner.Finding) []fileGroup {
	order := make(map[string]int)
	grouped := make(map[string][]scanner.Finding)
	for _, f := range findings {
		if _, ok := order[f.FilePath]; !ok {
			order[f.FilePath] = len(order)
		}
		grouped[f.FilePath] = append(grouped[f.FilePath], f)
	}
	result := make([]fileGroup, 0, len(grouped))
	for path, findings := range grouped {
		result = append(result, fileGroup{filePath: path, findings: findings})
	}
	sort.Slice(result, func(i, j int) bool {
		return order[result[i].filePath] < order[result[j].filePath]
	})
	return result
}
