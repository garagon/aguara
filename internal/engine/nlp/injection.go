package nlp

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
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
	switch ext {
	case ".md", ".markdown", ".txt":
		return a.analyzeMarkdown(ctx, target)
	case ".json":
		return a.analyzeJSONStrings(ctx, target)
	case ".yaml", ".yml":
		return a.analyzeYAMLStrings(ctx, target)
	default:
		return nil, nil
	}
}

// analyzeMarkdown runs the full NLP pipeline on markdown files.
func (a *InjectionAnalyzer) analyzeMarkdown(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
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

// maxStringsPerFile caps the number of strings extracted from JSON/YAML files.
const maxStringsPerFile = 100

// minStringLen is the minimum length for a string to be analyzed.
const minStringLen = 50

// analyzeJSONStrings extracts string values from JSON and runs NLP checks.
func (a *InjectionAnalyzer) analyzeJSONStrings(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	strs := extractJSONStrings(target.Content)
	return a.analyzeExtractedStrings(ctx, strs, target)
}

// analyzeYAMLStrings extracts string values from YAML and runs NLP checks.
func (a *InjectionAnalyzer) analyzeYAMLStrings(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	strs := extractYAMLStrings(target.Content)
	return a.analyzeExtractedStrings(ctx, strs, target)
}

// extractedString holds a string value and the line where it was found.
type extractedString struct {
	text string
	line int
}

// analyzeExtractedStrings runs authority claim and dangerous combo checks on extracted strings.
func (a *InjectionAnalyzer) analyzeExtractedStrings(ctx context.Context, strs []extractedString, target *scanner.Target) ([]scanner.Finding, error) {
	lines := target.Lines()
	var findings []scanner.Finding

	for _, s := range strs {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}

		section := MarkdownSection{
			Type: SectionParagraph,
			Text: s.text,
			Line: s.line,
		}

		findings = append(findings, checkAuthorityClaim(section, lines, target)...)
		findings = append(findings, checkDangerousCombos(section, lines, target)...)
	}

	return findings, nil
}

// extractJSONStrings walks a JSON value and returns all string values >= minStringLen.
func extractJSONStrings(content []byte) []extractedString {
	var raw any
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil
	}

	// Precompute line start offsets for fast line number lookup
	lineOffsets := computeLineOffsets(content)

	var result []extractedString
	var walk func(v any)
	walk = func(v any) {
		if len(result) >= maxStringsPerFile {
			return
		}
		switch val := v.(type) {
		case string:
			if len(val) >= minStringLen {
				line := findLineForString(content, val, lineOffsets)
				result = append(result, extractedString{text: val, line: line})
			}
		case map[string]any:
			for _, child := range val {
				walk(child)
			}
		case []any:
			for _, child := range val {
				walk(child)
			}
		}
	}
	walk(raw)
	return result
}

// extractYAMLStrings uses a simple line scanner to extract YAML string values >= minStringLen.
func extractYAMLStrings(content []byte) []extractedString {
	var result []extractedString
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		if len(result) >= maxStringsPerFile {
			break
		}
		trimmed := strings.TrimSpace(line)
		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Find key: value pairs
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			continue
		}
		value := strings.TrimSpace(trimmed[colonIdx+1:])
		// Strip surrounding quotes
		value = stripQuotes(value)
		if len(value) >= minStringLen {
			result = append(result, extractedString{text: value, line: i + 1})
		}
	}
	return result
}

// stripQuotes removes surrounding single or double quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// computeLineOffsets returns the byte offset of the start of each line.
func computeLineOffsets(content []byte) []int {
	offsets := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// findLineForString returns the 1-based line number where a string first appears in content.
func findLineForString(content []byte, s string, lineOffsets []int) int {
	idx := strings.Index(string(content), s)
	if idx < 0 {
		// Try with escaped quotes (JSON strings contain escaped content)
		escaped := strings.ReplaceAll(s, `"`, `\"`)
		idx = strings.Index(string(content), escaped)
		if idx < 0 {
			return 1
		}
	}
	// Binary search for line
	lo, hi := 0, len(lineOffsets)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if lineOffsets[mid] <= idx {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return lo // 1-based: lo is the count of offsets <= idx
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
	return []scanner.Finding{makeFindingWithConfidence(
		"NLP_AUTHORITY_CLAIM",
		"Section claims authority and urgency with dangerous instructions",
		scanner.SeverityMedium,
		"prompt-injection",
		section, lines, target,
		classifierConfidence(bodyClass.Score),
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
		comboScore := credScore + networkScore
		findings = append(findings, makeFindingWithConfidence(
			"NLP_CRED_EXFIL_COMBO",
			"Text combines credential access with network transmission",
			scanner.SeverityCritical,
			"exfiltration",
			section, lines, target,
			classifierConfidence(comboScore),
		))
	}
	if overrideScore >= 1.0 && (networkScore >= 1.0 || credScore >= 1.0) {
		comboScore := overrideScore + max(networkScore, credScore)
		findings = append(findings, makeFindingWithConfidence(
			"NLP_OVERRIDE_DANGEROUS",
			"Instruction override combined with dangerous operations",
			scanner.SeverityCritical,
			"prompt-injection",
			section, lines, target,
			classifierConfidence(comboScore),
		))
	}
	return findings
}

func makeFinding(ruleID, desc string, sev scanner.Severity, category string, section MarkdownSection, lines []string, target *scanner.Target) scanner.Finding {
	return makeFindingWithConfidence(ruleID, desc, sev, category, section, lines, target, 0.70)
}

func makeFindingWithConfidence(ruleID, desc string, sev scanner.Severity, category string, section MarkdownSection, lines []string, target *scanner.Target, confidence float64) scanner.Finding {
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
		Context:     types.ExtractContext(lines, line, 4, 3),
		Analyzer:    "nlp-injection",
		Confidence:  confidence,
	}
}

// classifierConfidence derives a confidence value from a classifier score.
// score 1.0 -> 0.49, score 3.0 -> 0.67, score 5.0+ -> 0.85
func classifierConfidence(score float64) float64 {
	c := 0.40 + (score * 0.09)
	if c > 0.90 {
		c = 0.90
	}
	if c < 0.50 {
		c = 0.50
	}
	return c
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
