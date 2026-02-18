package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
)

// MarkdownFormatter outputs findings as GitHub-flavored markdown,
// designed for GitHub Actions Job Summaries and PR comments.
type MarkdownFormatter struct{}

func (f *MarkdownFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	if len(result.Findings) == 0 {
		f.printClean(w, result)
		return nil
	}

	counts := f.countBySeverity(result.Findings)
	f.printSummary(w, result, counts)
	f.printFindings(w, result.Findings)
	f.printFooter(w, result)
	return nil
}

func (f *MarkdownFormatter) printClean(w io.Writer, result *scanner.ScanResult) {
	fmt.Fprintf(w, "### :white_check_mark: Aguara Security Scan — No issues found\n\n")
	fmt.Fprintf(w, "> %d files scanned · %d rules · %.2fs\n",
		result.FilesScanned, result.RulesLoaded, result.Duration.Seconds())
}

func (f *MarkdownFormatter) printSummary(w io.Writer, result *scanner.ScanResult, counts map[scanner.Severity]int) {
	total := len(result.Findings)

	fmt.Fprintf(w, "### :rotating_light: Aguara Security Scan — %d findings\n\n", total)

	fmt.Fprintf(w, "> **Target:** `%s` · %d files · %d rules · %.2fs\n\n",
		result.Target, result.FilesScanned, result.RulesLoaded, result.Duration.Seconds())

	// Severity badges
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}
	var badges []string
	for _, sev := range severities {
		c := counts[sev]
		if c == 0 {
			continue
		}
		badges = append(badges, fmt.Sprintf("%s **%d %s**", severityEmoji(sev), c, sev.String()))
	}
	fmt.Fprintf(w, "%s\n\n", strings.Join(badges, " · "))
}

func (f *MarkdownFormatter) printFindings(w io.Writer, findings []scanner.Finding) {
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}

	for _, sev := range severities {
		filtered := filterBySeverity(findings, sev)
		if len(filtered) == 0 {
			continue
		}

		emoji := severityEmoji(sev)
		label := sev.String()

		fmt.Fprintf(w, "<details%s>\n", openByDefault(sev))
		fmt.Fprintf(w, "<summary>%s <strong>%s (%d)</strong></summary>\n\n", emoji, label, len(filtered))

		fmt.Fprintf(w, "| Rule | Description | File | Line |\n")
		fmt.Fprintf(w, "|------|-------------|------|------|\n")

		grouped := groupByFile(filtered)
		for _, group := range grouped {
			for _, finding := range group.findings {
				matched := truncateMarkdown(finding.MatchedText, 60)
				desc := finding.RuleName
				if matched != "" {
					desc += fmt.Sprintf("<br><code>%s</code>", escapeMarkdown(matched))
				}
				fmt.Fprintf(w, "| `%s` | %s | `%s` | L%d |\n",
					finding.RuleID, desc, finding.FilePath, finding.Line)
			}
		}

		fmt.Fprintf(w, "\n</details>\n\n")
	}
}

func (f *MarkdownFormatter) printFooter(w io.Writer, result *scanner.ScanResult) {
	// Top affected files
	fileCounts := map[string]int{}
	for _, finding := range result.Findings {
		fileCounts[finding.FilePath]++
	}
	type fc struct {
		path  string
		count int
	}
	sorted := make([]fc, 0, len(fileCounts))
	for path, count := range fileCounts {
		sorted = append(sorted, fc{path, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].path < sorted[j].path
	})

	if len(sorted) > 1 {
		limit := min(len(sorted), 5)
		fmt.Fprintf(w, "**Top affected files:**\n\n")
		fmt.Fprintf(w, "| File | Findings |\n")
		fmt.Fprintf(w, "|------|----------|\n")
		for i := range limit {
			fmt.Fprintf(w, "| `%s` | %d |\n", sorted[i].path, sorted[i].count)
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "---\n")
	fmt.Fprintf(w, "*Scanned by [Aguara](https://github.com/garagon/aguara) %s*\n", ToolVersion)
}

func (f *MarkdownFormatter) countBySeverity(findings []scanner.Finding) map[scanner.Severity]int {
	counts := map[scanner.Severity]int{}
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

func severityEmoji(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return ":red_circle:"
	case scanner.SeverityHigh:
		return ":orange_circle:"
	case scanner.SeverityMedium:
		return ":yellow_circle:"
	case scanner.SeverityLow:
		return ":blue_circle:"
	case scanner.SeverityInfo:
		return ":white_circle:"
	default:
		return ":black_circle:"
	}
}

func openByDefault(sev scanner.Severity) string {
	if sev == scanner.SeverityCritical || sev == scanner.SeverityHigh {
		return " open"
	}
	return ""
}

func truncateMarkdown(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
