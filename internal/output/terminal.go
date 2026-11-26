package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// ANSI color codes
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	underline = "\033[4m"
	red       = "\033[31m"
	green     = "\033[32m"
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
	// Width is the rendering width for separators and section headers.
	// Zero falls back to the 72-column default.
	Width int
	// Detections is the number of rules in the catalog the scan used
	// (pattern and analyzer rules). Zero reports only the compiled
	// pattern rule count.
	Detections int
}

func (f *TerminalFormatter) width() int {
	if f.Width > 0 {
		return f.Width
	}
	return lineWidth
}

func (f *TerminalFormatter) color(code, text string) string {
	if f.NoColor {
		return text
	}
	return code + text + reset
}

func (f *TerminalFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	if !f.NoColor && os.Getenv("NO_COLOR") != "" {
		f.NoColor = true
	}

	f.printHeader(w, result)

	switch {
	case len(result.Findings) == 0 && result.FilesScanned == 0:
		// Zero files is not a clean result: nothing was evaluated.
		st := NewStyle(f.NoColor)
		fmt.Fprintf(w, "\n  %s %s\n", st.SeverityIcon("MEDIUM"), st.Yellow(NothingScannedMessage(result)))
	case len(result.Findings) == 0:
		fmt.Fprintf(w, "\n  %s\n", NewStyle(f.NoColor).OK("No security issues found."))
	default:
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
	return strings.Repeat("\u2500", f.width())
}

func (f *TerminalFormatter) sectionHeader(title string) string {
	prefix := "\u2500\u2500 " + title + " "
	displayLen := utf8.RuneCountInString(prefix)
	remaining := max(f.width()-displayLen, 0)
	return prefix + strings.Repeat("\u2500", remaining)
}

func (f *TerminalFormatter) printHeader(w io.Writer, result *scanner.ScanResult) {
	sep := f.separator()
	fmt.Fprintf(w, "\n%s\n", f.color(dim, sep))
	fmt.Fprintf(w, "  %s\n", f.color(bold, "AGUARA SCAN"))

	parts := []string{}
	if result.Target != "" {
		parts = append(parts, fmt.Sprintf("Target: %s", TerminalText(result.Target)))
	}
	parts = append(parts, fmt.Sprintf("%d files", result.FilesScanned))
	parts = append(parts, RulesLabel(f.Detections, result.RulesLoaded))
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
		fmt.Fprintf(w, "\n  %s\n", f.color(bold+underline, TerminalText(group.filePath)))
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
	fmt.Fprintln(w)
	f.printFindingHead(w, finding)

	if finding.MatchedText != "" {
		evidence := TerminalText(finding.MatchedText)
		if !f.Verbose {
			evidence = truncate(evidence, previewWidth)
		}
		f.printDetail(w, "", evidence, dim)
	}
	if f.Verbose && finding.Description != "" {
		f.printDetail(w, "", TerminalText(finding.Description), yellow)
	}
	if finding.Remediation != "" {
		f.printDetail(w, "Fix: ", TerminalText(finding.Remediation), cyan)
	}
	f.printAlsoMatched(w, finding)
}

func (f *TerminalFormatter) printFindingCompact(w io.Writer, finding scanner.Finding) {
	f.printFindingHead(w, finding)
	if f.Verbose && finding.MatchedText != "" {
		f.printDetail(w, "", TerminalText(finding.MatchedText), dim)
	}
	if f.Verbose && finding.Severity >= scanner.SeverityHigh && finding.Description != "" {
		f.printDetail(w, "", TerminalText(finding.Description), yellow)
	}
	if f.Verbose && finding.Remediation != "" {
		f.printDetail(w, "Fix: ", TerminalText(finding.Remediation), cyan)
	}
	f.printAlsoMatched(w, finding)
}

// printFindingHead prints the icon, rule ID, rule name and location of a
// finding in aligned columns. Rule IDs are never cut, so they can be pasted
// into `aguara explain`. A rule name longer than its column is printed in
// full: on a terminal the location then moves to its own line and long
// text wraps at the terminal width; elsewhere the line simply runs longer.
func (f *TerminalFormatter) printFindingHead(w io.Writer, finding scanner.Finding) {
	f.writeFindingHead(w, finding, "    ")
}

// WriteFindingLine writes the one-line summary of a finding (icon, rule ID,
// rule name, location) the way the scan report lays it out, followed by
// the "+N more on this line" hint when deduplication merged other findings
// into it. indent is the leading indentation.
func (f *TerminalFormatter) WriteFindingLine(w io.Writer, finding scanner.Finding, indent string) {
	f.writeFindingHead(w, finding, indent)
	f.printAlsoMatched(w, finding)
}

func (f *TerminalFormatter) writeFindingHead(w io.Writer, finding scanner.Finding, indent string) {
	icon := f.severityIcon(finding.Severity)
	ruleID := TerminalText(finding.RuleID)
	idCell := fmt.Sprintf("%-*s", ruleIDWidth, ruleID)
	name := oneLine(TerminalText(finding.RuleName))
	loc := fmt.Sprintf("%s:%d", TerminalText(finding.FilePath), finding.Line)
	locStyled := f.color(cyan, loc)
	if finding.InCodeBlock {
		loc += " [code]"
		locStyled += " " + f.color(dim, "[code]")
	}
	if f.Verbose && finding.Confidence > 0 {
		conf := fmt.Sprintf("[%d%%]", int(finding.Confidence*100))
		loc += " " + conf
		locStyled += " " + f.color(dim, conf)
	}

	// Display columns before the name: indent, icon, space, ID cell, space.
	nameCol := len(indent) + 2 + displayWidth(idCell) + 1
	if displayWidth(name) <= nameWidth {
		line := nameCol + nameWidth + 1 + displayWidth(loc)
		if f.Width <= 0 || line <= f.Width {
			fmt.Fprintf(w, "%s%s %s %s %s\n", indent, icon, f.color(bold, idCell), fmt.Sprintf("%-*s", nameWidth, name), locStyled)
			return
		}
	} else if f.Width <= 0 {
		fmt.Fprintf(w, "%s%s %s %s %s\n", indent, icon, f.color(bold, idCell), name, locStyled)
		return
	}
	// A line the rule ID already fills (a long ID, a narrow terminal)
	// moves the name and the location below it, under the rule ID.
	locPad := strings.Repeat(" ", len(indent)+2)
	under := max(f.Width-len(locPad), minWrapWidth)
	if f.Width-nameCol < minWrapWidth {
		fmt.Fprintf(w, "%s%s %s\n", indent, icon, f.color(bold, ruleID))
		for _, l := range wrapText(name, under) {
			fmt.Fprintf(w, "%s%s\n", locPad, l)
		}
		for _, l := range wrapText(loc, under) {
			fmt.Fprintf(w, "%s%s\n", locPad, f.color(cyan, l))
		}
		return
	}
	// Terminal output that does not fit: wrap the name under its column
	// and put the location on the next line, aligned with the name.
	pad := strings.Repeat(" ", nameCol)
	nameLines := wrapText(name, f.Width-nameCol)
	fmt.Fprintf(w, "%s%s %s %s\n", indent, icon, f.color(bold, idCell), nameLines[0])
	for _, l := range nameLines[1:] {
		fmt.Fprintf(w, "%s%s\n", pad, l)
	}
	if nameCol+displayWidth(loc) <= f.Width {
		fmt.Fprintf(w, "%s%s\n", pad, locStyled)
		return
	}
	// A path longer than the rest of the line starts under the rule ID
	// and is split rather than cut.
	for _, l := range wrapText(loc, under) {
		fmt.Fprintf(w, "%s%s\n", locPad, f.color(cyan, l))
	}
}

// minWrapWidth is the narrowest column wrapped text is fitted into; text
// in a narrower space moves to its own line instead of overflowing.
const minWrapWidth = 20

// printDetail prints one "│ " detail line (evidence, description, fix),
// wrapped at the terminal width when output goes to a terminal.
func (f *TerminalFormatter) printDetail(w io.Writer, label, text, code string) {
	const prefix = "      "
	bar := f.color(dim, "\u2502")
	text = oneLine(text)
	if f.Width <= 0 {
		if label != "" {
			fmt.Fprintf(w, "%s%s %s%s\n", prefix, bar, f.color(dim, label), f.color(code, text))
			return
		}
		fmt.Fprintf(w, "%s%s %s\n", prefix, bar, f.color(code, text))
		return
	}
	avail := max(f.Width-len(prefix)-2-displayWidth(label), 20)
	for i, l := range wrapText(text, avail) {
		lead := label
		if i > 0 {
			lead = strings.Repeat(" ", displayWidth(label))
		}
		if lead != "" {
			fmt.Fprintf(w, "%s%s %s%s\n", prefix, bar, f.color(dim, lead), f.color(code, l))
			continue
		}
		fmt.Fprintf(w, "%s%s %s\n", prefix, bar, f.color(code, l))
	}
}

// printAlsoMatched names the findings deduplication merged into this one,
// so a single-line input does not hide what else matched it.
func (f *TerminalFormatter) printAlsoMatched(w io.Writer, finding scanner.Finding) {
	if len(finding.AlsoMatched) == 0 {
		return
	}
	ids := make([]string, 0, len(finding.AlsoMatched))
	for _, m := range finding.AlsoMatched {
		ids = append(ids, TerminalText(m.RuleID))
	}
	f.printDetail(w, "", fmt.Sprintf("+%d more on this line: %s", len(ids), strings.Join(ids, ", ")), dim)
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
		fmt.Fprintf(w, "  %4d  %s\n", sorted[i].count, TerminalText(sorted[i].path))
	}
}

func (f *TerminalFormatter) printFooter(w io.Writer, result *scanner.ScanResult) {
	sep := f.separator()
	fmt.Fprintf(w, "\n%s\n", f.color(dim, sep))

	rules := fmt.Sprintf("%d pattern rules", result.RulesLoaded)
	if f.Detections > 0 {
		rules = fmt.Sprintf("%d detections", f.Detections)
	}
	parts := []string{
		filesScannedLabel(result),
		fmt.Sprintf("%d findings", len(result.Findings)),
		rules,
	}
	if result.RiskScore > 0 {
		parts = append(parts, fmt.Sprintf("risk: %.1f/100", result.RiskScore))
	}
	if result.Duration > 0 {
		parts = append(parts, fmt.Sprintf("%.2fs", result.Duration.Seconds()))
	}

	fmt.Fprintf(w, "  %s\n", strings.Join(parts, " \u00b7 "))

	if b := result.Baseline; b != nil && b.Applied {
		line := fmt.Sprintf("baseline: %d new \u00b7 %d baselined \u00b7 %d gating", b.New, b.Baselined, b.GateCount)
		if b.NonBaselineable > 0 {
			line += fmt.Sprintf(" (incl. %d non-baselineable, always reported)", b.NonBaselineable)
		}
		fmt.Fprintf(w, "  %s\n", f.color(dim, line))
	}
	if line := SuppressionLine(result.Suppressed); line != "" {
		for _, l := range wrapText(line, f.Width-2) {
			fmt.Fprintf(w, "  %s\n", f.color(dim, l))
		}
	}
	fmt.Fprintf(w, "%s\n", f.color(dim, sep))

	if rule := topRuleID(result.Findings); rule != "" {
		fmt.Fprintf(w, "  %s\n", f.color(dim, "Next: aguara explain "+TerminalText(rule)))
	}
	if !f.Verbose && hasBelowCritical(result.Findings) {
		fmt.Fprintf(w, "  %s\n", f.color(dim, "Run with -v to show evidence and fixes for every finding."))
	}
}

// RulesLabel describes the rules a scan ran: "259 detections (191 pattern
// rules)" when the catalog size is known, else "191 pattern rules". A
// detection is any catalog rule, pattern or analyzer-emitted; pattern rules
// are the compiled YAML rules that rules_loaded counts.
func RulesLabel(detections, patternRules int) string {
	if detections > 0 {
		return fmt.Sprintf("%d detections (%d pattern rules)", detections, patternRules)
	}
	return fmt.Sprintf("%d pattern rules", patternRules)
}

// SuppressionLine summarizes what the report does not list separately:
// findings merged into another on the same line and findings removed by
// filters. Empty when nothing was suppressed.
func SuppressionLine(s *types.SuppressionSummary) string {
	if s == nil {
		return ""
	}
	var parts []string
	add := func(n int, text string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, text))
		}
	}
	add(s.Deduplicated, "merged into findings on the same line")
	add(s.BelowMinSeverity, "below the minimum severity")
	add(s.DisabledRules, "from disabled rules")
	add(s.ToolExemptions, "exempt for the tool")
	add(s.InlineDirectives, "suppressed by inline directives")
	if len(parts) == 0 && s.ExcludedFiles == 0 {
		return ""
	}
	line := "not listed separately: " + strings.Join(parts, " \u00b7 ")
	if len(parts) == 0 {
		line = ""
	}
	if s.ExcludedFiles > 0 {
		files := fmt.Sprintf("%d %s excluded by ignore patterns", s.ExcludedFiles, plural(s.ExcludedFiles, "file", "files"))
		if line == "" {
			return files
		}
		line += " \u00b7 " + files
	}
	return line
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func hasBelowCritical(findings []scanner.Finding) bool {
	for _, f := range findings {
		if f.Severity < scanner.SeverityCritical {
			return true
		}
	}
	return false
}

// NothingScannedMessage explains a scan that evaluated zero files, in
// terms of what it was asked to scan.
func NothingScannedMessage(result *scanner.ScanResult) string {
	if result.Coverage != nil {
		switch result.Coverage.Scope {
		case types.ScanScopeChanged:
			return "Nothing was scanned: no changed files under the target."
		case types.ScanScopeAuto:
			return "Nothing was scanned: no MCP client configuration files were found."
		}
	}
	return "Nothing was scanned: no scannable files under the target. This is not a clean result."
}

// filesScannedLabel states how many files were evaluated and, when the
// scan was limited, which ones ("3 changed files scanned").
func filesScannedLabel(result *scanner.ScanResult) string {
	noun := "files"
	if result.Coverage != nil {
		switch result.Coverage.Scope {
		case types.ScanScopeChanged:
			noun = "changed " + noun
		case types.ScanScopeAuto:
			noun = "MCP config " + noun
		}
	}
	return fmt.Sprintf("%d %s scanned", result.FilesScanned, noun)
}

// topRuleID returns the rule behind the most severe finding -- the one
// the Next hint points `aguara explain` at.
func topRuleID(findings []scanner.Finding) string {
	best := -1
	rule := ""
	for _, f := range findings {
		if int(f.Severity) > best {
			best = int(f.Severity)
			rule = f.RuleID
		}
	}
	return rule
}

func (f *TerminalFormatter) severityIcon(sev scanner.Severity) string {
	return NewStyle(f.NoColor).SeverityIcon(sev.String())
}

func (f *TerminalFormatter) severityColor(sev scanner.Severity) string {
	return severityCode(sev.String())
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

// oneLine replaces layout characters that would break a terminal line.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\t", " ")
}

// displayWidth is the number of columns s occupies, counting one per rune.
func displayWidth(s string) int {
	return utf8.RuneCountInString(s)
}

// wrapText splits s into lines of at most width columns, breaking at
// spaces and splitting words longer than a line. It always returns at
// least one line.
func wrapText(s string, width int) []string {
	if width <= 0 || displayWidth(s) <= width {
		return []string{s}
	}
	var lines []string
	var cur []rune
	for _, word := range strings.Fields(s) {
		runes := []rune(word)
		for len(runes) > 0 {
			switch {
			case len(cur) == 0 && len(runes) <= width:
				cur = append(cur, runes...)
				runes = nil
			case len(cur) == 0:
				lines = append(lines, string(runes[:width]))
				runes = runes[width:]
			case len(cur)+1+len(runes) <= width:
				cur = append(append(cur, ' '), runes...)
				runes = nil
			default:
				lines = append(lines, string(cur))
				cur = nil
			}
		}
	}
	if len(cur) > 0 || len(lines) == 0 {
		lines = append(lines, string(cur))
	}
	return lines
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return strings.Repeat(".", max(maxLen, 0))
	}
	// Preserve the byte budget without splitting a UTF-8 character.
	end := maxLen - 3
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "..."
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
