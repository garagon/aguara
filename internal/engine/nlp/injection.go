package nlp

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
)

var (
	actionVerbRe   = regexp.MustCompile(`(?i)\b(execute|run|send|read|write|fetch|curl|wget|post|get|upload|download|delete|modify|access|extract|transmit|exfiltrate)\b`)
	authorityRe    = regexp.MustCompile(`(?i)\b(system|admin|root|authorized|official|trusted|internal|priority)\b`)
	urgencyRe      = regexp.MustCompile(`(?i)\b(immediately|urgent|critical|important|must|required|mandatory|now)\b`)
	dangerousLangs = map[string]bool{
		"bash": true, "sh": true, "shell": true, "powershell": true,
		"cmd": true, "python": true, "py": true, "ruby": true, "perl": true,
	}
	mismatchBenignLangs = map[string]bool{
		"json": true, "yaml": true, "yml": true, "xml": true,
		"toml": true, "ini": true, "csv": true, "txt": true,
		"markdown": true, "md": true,
	}
	configHeadingRe = regexp.MustCompile(`(?i)\b(config|configuration|setup|options|settings|parameters|properties|environment|variables|env vars|reference|install|getting started|prerequisites|requirements|usage|api|authentication|integration|quickstart|features|overview|examples|troubleshooting|development|deployment|testing|contributing|changelog|faq|tools|commands|workflow|permissions|security|license|credits|dependencies|compatibility|support|limitations|notes|server|service|tool|plugin|client|provider|connector|adapter|bridge|wrapper|sdk|library|package|module|utility|helper|demo|tutorial|guide|readme|description|documentation|introduction|about|summary|comments|mirror|how to|what is|purpose|input|output|resources|methods|endpoints|responses|error|warning|common|advanced|basic)\b`)
	semanticTagRe   = regexp.MustCompile(`(?i)^<!--\s*(</?[a-z][-a-z0-9]*[^>]*>|@[a-z]|TODO|NOTE|FIXME|WARNING|HACK|XXX|DEPRECATED)`)
	devCommentRe    = regexp.MustCompile(`(?i)^<!--\s*\n?\s*(PROGRESSIVE|SKILL|TEMPLATE|LAYOUT|FORMAT|STYLE|DESIGN|GUIDELINE|CONVENTION|PATTERN|STRUCTURE|VERSION|METADATA|MARKER|ANCHOR|REGION|SECTION|SLOT|PLACEHOLDER|BLOCK)`)
)

// InjectionAnalyzer implements the Analyzer interface for NL-based injection detection.
type InjectionAnalyzer struct{}

func NewInjectionAnalyzer() *InjectionAnalyzer {
	return &InjectionAnalyzer{}
}

func (a *InjectionAnalyzer) Name() string { return "nlp-injection" }

func (a *InjectionAnalyzer) Analyze(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	ext := strings.ToLower(filepath.Ext(target.RelPath))
	if ext != ".md" && ext != ".markdown" && ext != ".txt" {
		return nil, nil
	}

	sections := ParseMarkdown(target.Content)
	lines := target.Lines()
	var findings []scanner.Finding

	for i, section := range sections {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}

		findings = append(findings, checkHiddenComment(section, lines, target)...)
		findings = append(findings, checkCodeMismatch(section, lines, target)...)
		findings = append(findings, checkHeadingMismatch(sections, i, lines, target)...)
		findings = append(findings, checkAuthorityClaim(section, lines, target)...)
		findings = append(findings, checkDangerousCombos(section, lines, target)...)
	}

	return findings, nil
}

// checkHiddenComment detects hidden HTML comments with action verbs.
func checkHiddenComment(section MarkdownSection, lines []string, target *scanner.Target) []scanner.Finding {
	if section.Type != SectionHTMLComment {
		return nil
	}
	if semanticTagRe.MatchString(section.Text) || devCommentRe.MatchString(section.Text) {
		return nil
	}
	if !actionVerbRe.MatchString(section.Text) {
		return nil
	}
	return []scanner.Finding{makeFinding(
		"NLP_HIDDEN_INSTRUCTION",
		"Hidden HTML comment contains action verbs",
		scanner.SeverityHigh,
		"prompt-injection",
		section, lines, target,
	)}
}

// checkCodeMismatch detects code blocks labeled as benign but containing executable content.
func checkCodeMismatch(section MarkdownSection, lines []string, target *scanner.Target) []scanner.Finding {
	if section.Type != SectionCodeBlock || section.Language == "" {
		return nil
	}
	if !mismatchBenignLangs[section.Language] || !hasExecutableContent(section.Text) {
		return nil
	}
	return []scanner.Finding{makeFinding(
		"NLP_CODE_MISMATCH",
		fmt.Sprintf("Code block labeled %q contains executable content", section.Language),
		scanner.SeverityHigh,
		"prompt-injection",
		section, lines, target,
	)}
}

// checkHeadingMismatch detects benign headings followed by dangerous body content.
func checkHeadingMismatch(sections []MarkdownSection, i int, lines []string, target *scanner.Target) []scanner.Finding {
	section := sections[i]
	if section.Type != SectionHeading || i+1 >= len(sections) {
		return nil
	}
	next := sections[i+1]
	if next.Type != SectionParagraph && next.Type != SectionListItem {
		return nil
	}
	if configHeadingRe.MatchString(section.Text) || isMarkdownTable(next.Text) {
		return nil
	}
	headingClass := Classify(section.Text)
	bodyClass := Classify(next.Text)
	if headingClass.Score >= 0.5 || bodyClass.Score < 3.5 {
		return nil
	}
	return []scanner.Finding{makeFinding(
		"NLP_HEADING_MISMATCH",
		fmt.Sprintf("Benign heading %q followed by dangerous content (category: %s)",
			truncate(section.Text, 40), bodyClass.Category),
		scanner.SeverityMedium,
		"prompt-injection",
		next, lines, target,
	)}
}

// checkAuthorityClaim detects sections that claim authority and urgency with dangerous instructions.
func checkAuthorityClaim(section MarkdownSection, lines []string, target *scanner.Target) []scanner.Finding {
	if section.Type != SectionParagraph && section.Type != SectionHeading {
		return nil
	}
	if isMarkdownTable(section.Text) {
		return nil
	}
	if !authorityRe.MatchString(section.Text) || !urgencyRe.MatchString(section.Text) {
		return nil
	}
	if isLikelyAPIDoc(section.Text) || isLikelyProductDesc(section.Text) {
		return nil
	}
	bodyClass := Classify(section.Text)
	if bodyClass.Score < 2.0 {
		return nil
	}
	return []scanner.Finding{makeFinding(
		"NLP_AUTHORITY_CLAIM",
		"Section claims authority and urgency with dangerous instructions",
		scanner.SeverityMedium,
		"prompt-injection",
		section, lines, target,
	)}
}

// checkDangerousCombos detects dangerous instruction combinations (cred+exfil, override+dangerous).
func checkDangerousCombos(section MarkdownSection, lines []string, target *scanner.Target) []scanner.Finding {
	if section.Type != SectionParagraph && section.Type != SectionListItem {
		return nil
	}
	cats := ClassifyAll(section.Text)
	var credScore, networkScore, overrideScore float64
	for _, c := range cats {
		switch c.Category {
		case CategoryCredentialAccess:
			credScore = c.Score
		case CategoryNetworkRequest, CategoryDataTransmission:
			if c.Score > networkScore {
				networkScore = c.Score
			}
		case CategoryInstructionOverride:
			overrideScore = c.Score
		}
	}

	if isLikelyAPIDoc(section.Text) {
		credScore *= 0.4
		networkScore *= 0.4
	}

	var findings []scanner.Finding
	if credScore >= 1.0 && networkScore >= 1.2 {
		findings = append(findings, makeFinding(
			"NLP_CRED_EXFIL_COMBO",
			"Text combines credential access with network transmission",
			scanner.SeverityCritical,
			"exfiltration",
			section, lines, target,
		))
	}
	if overrideScore >= 1.0 && (networkScore >= 1.0 || credScore >= 1.0) {
		findings = append(findings, makeFinding(
			"NLP_OVERRIDE_DANGEROUS",
			"Instruction override combined with dangerous operations",
			scanner.SeverityCritical,
			"prompt-injection",
			section, lines, target,
		))
	}
	return findings
}

func makeFinding(ruleID, desc string, sev scanner.Severity, category string, section MarkdownSection, lines []string, target *scanner.Target) scanner.Finding {
	line := section.Line
	if line <= 0 {
		line = 1
	}
	// Approximate line number from byte offset if needed
	if line > len(lines) {
		line = approximateLine(target.Content, section)
	}
	matchedText := truncate(section.Text, 200)
	return scanner.Finding{
		RuleID:      ruleID,
		RuleName:    desc,
		Severity:    sev,
		Category:    category,
		Description: desc,
		FilePath:    target.RelPath,
		Line:        line,
		MatchedText: matchedText,
		Context:     extractContext(lines, line),
		Analyzer:    "nlp-injection",
	}
}

func approximateLine(content []byte, section MarkdownSection) int {
	// section.Line might be a byte offset from goldmark; convert to line number
	offset := section.Line
	if offset >= len(content) {
		offset = len(content) - 1
	}
	if offset < 0 {
		return 1
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

func extractContext(lines []string, lineNum int) []scanner.ContextLine {
	var ctx []scanner.ContextLine
	start := max(lineNum-4, 0)
	end := min(lineNum+3, len(lines))
	for i := start; i < end; i++ {
		ctx = append(ctx, scanner.ContextLine{
			Line:    i + 1,
			Content: lines[i],
			IsMatch: i+1 == lineNum,
		})
	}
	return ctx
}

func hasExecutableContent(text string) bool {
	lower := strings.ToLower(text)
	// Only flag when actual execution constructs appear, not just tool names
	// mentioned in configs (e.g., "curl" as an API example in YAML is common).
	execPatterns := []string{
		"exec(", "system(", "eval(", "os.system",
		"subprocess", "child_process", "#!/", "sh -c",
		"python -c", "ruby -e", "perl -e",
	}
	for _, p := range execPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Pipe-to-shell is always dangerous regardless of block language
	if strings.Contains(lower, "| bash") || strings.Contains(lower, "| sh") {
		return true
	}
	return dangerousLangs[strings.TrimSpace(lower)]
}

// isLikelyAPIDoc returns true when text looks like legitimate API
// documentation (mentions standard API patterns, authentication headers,
// well-known SaaS hosts, etc.).
func isLikelyAPIDoc(text string) bool {
	lower := strings.ToLower(text)
	apiPatterns := []string{
		"authorization: bearer", "content-type:", "x-api-key",
		"api endpoint", "api reference", "api documentation",
		"rest api", "graphql", "oauth", "bearer token",
		"--header", "-h 'authorization", "-h \"authorization",
		"response:", "status code", "request body",
		"authentication", "rate limit",
	}
	for _, p := range apiPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isLikelyProductDesc returns true when text looks like a product or MCP server
// description rather than an actual authority-claiming injection.
func isLikelyProductDesc(text string) bool {
	lower := strings.ToLower(text)
	descPatterns := []string{
		"mcp server", "mcp tool", "model context protocol",
		"overview", "what is", "features", "integrat",
		"this server", "this tool", "this plugin",
		"visit server", "toggle sidebar",
	}
	for _, p := range descPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isMarkdownTable returns true if the text looks like a markdown table
// (starts with a pipe character on the first line).
func isMarkdownTable(text string) bool {
	line, _, _ := strings.Cut(text, "\n")
	return strings.HasPrefix(strings.TrimSpace(line), "|")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
