// Package pattern implements Layer 1 detection: regex and contains matching
// with base64/hex decoding, code block awareness, and exclude patterns.
package pattern

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

const contextRadius = 3

// Matcher implements the Analyzer interface using compiled pattern rules.
type Matcher struct {
	rules []*rules.CompiledRule
}

// NewMatcher creates a new pattern matcher with the given compiled rules.
func NewMatcher(compiled []*rules.CompiledRule) *Matcher {
	return &Matcher{rules: compiled}
}

func (m *Matcher) Name() string { return "pattern" }

func (m *Matcher) Analyze(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	content := string(target.Content)
	lines := target.Lines()

	// Build code block map for markdown files
	var cbMap []bool
	if isMarkdown(target.RelPath) {
		cbMap = BuildCodeBlockMap(lines)
	}

	for _, rule := range m.rules {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		if !matchesTarget(rule.Targets, target.RelPath) {
			continue
		}

		switch rule.MatchMode {
		case rules.MatchAny:
			findings = append(findings, m.matchAny(rule, content, lines, target, cbMap)...)
		case rules.MatchAll:
			findings = append(findings, m.matchAll(rule, content, lines, target, cbMap)...)
		}
	}

	// Phase 4: decode base64/hex blobs and re-scan
	findings = append(findings, DecodeAndRescan(target, m.rules, cbMap)...)

	return findings, nil
}

func (m *Matcher) matchAny(rule *rules.CompiledRule, content string, lines []string, target *scanner.Target, cbMap []bool) []scanner.Finding {
	var findings []scanner.Finding
	for _, pat := range rule.Patterns {
		hits := matchPattern(pat, content, lines)
		for _, hit := range hits {
			if isExcluded(rule.ExcludePatterns, lines, hit.line) {
				continue
			}
			sev := rule.Severity
			inCB := isInCodeBlock(cbMap, hit.line)
			if inCB {
				sev = types.DowngradeSeverity(sev)
			}
			findings = append(findings, scanner.Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    sev,
				Category:    rule.Category,
				Description: rule.Description,
				FilePath:    target.RelPath,
				Line:        hit.line,
				MatchedText: hit.text,
				Context:     extractContext(lines, hit.line, contextRadius),
				Analyzer:    "pattern",
				InCodeBlock: inCB,
			})
		}
	}
	return findings
}

func (m *Matcher) matchAll(rule *rules.CompiledRule, content string, lines []string, target *scanner.Target, cbMap []bool) []scanner.Finding {
	// All patterns must have at least one hit
	var allHits [][]matchHit
	for _, pat := range rule.Patterns {
		hits := matchPattern(pat, content, lines)
		if len(hits) == 0 {
			return nil
		}
		allHits = append(allHits, hits)
	}
	// Use the first hit of the first pattern as the finding location
	firstHit := allHits[0][0]
	if isExcluded(rule.ExcludePatterns, lines, firstHit.line) {
		return nil
	}
	var matchedParts []string
	for _, hits := range allHits {
		matchedParts = append(matchedParts, hits[0].text)
	}
	sev := rule.Severity
	inCB := isInCodeBlock(cbMap, firstHit.line)
	if inCB {
		sev = types.DowngradeSeverity(sev)
	}
	return []scanner.Finding{{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    sev,
		Category:    rule.Category,
		Description: rule.Description,
		FilePath:    target.RelPath,
		Line:        firstHit.line,
		MatchedText: strings.Join(matchedParts, " + "),
		Context:     extractContext(lines, firstHit.line, contextRadius),
		Analyzer:    "pattern",
		InCodeBlock: inCB,
	}}
}

type matchHit struct {
	line int
	text string
}

// isExcluded returns true if the matched line or nearby context (3 lines before)
// matches any exclude pattern. This allows heading-based exclusions like
// "## Installation" to suppress matches on following lines.
func isExcluded(excludes []rules.CompiledPattern, lines []string, lineNum int) bool {
	if len(excludes) == 0 || lineNum < 1 || lineNum > len(lines) {
		return false
	}
	// Check the matched line and up to 3 lines before it
	start := max(lineNum-3, 1)
	for _, ep := range excludes {
		for i := start; i <= lineNum; i++ {
			line := lines[i-1]
			switch ep.Type {
			case rules.PatternRegex:
				if ep.Regex != nil && ep.Regex.MatchString(line) {
					return true
				}
			case rules.PatternContains:
				if strings.Contains(strings.ToLower(line), ep.Value) {
					return true
				}
			}
		}
	}
	return false
}

func matchPattern(pat rules.CompiledPattern, content string, lines []string) []matchHit {
	var hits []matchHit
	switch pat.Type {
	case rules.PatternRegex:
		if pat.Regex == nil {
			return nil
		}
		locs := pat.Regex.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			line := lineNumberAtOffset(content, loc[0])
			matched := content[loc[0]:loc[1]]
			if len(matched) > 200 {
				matched = matched[:200] + "..."
			}
			hits = append(hits, matchHit{line: line, text: matched})
		}
	case rules.PatternContains:
		lower := strings.ToLower(content)
		target := pat.Value // already lowercased during compilation
		idx := 0
		for {
			pos := strings.Index(lower[idx:], target)
			if pos == -1 {
				break
			}
			absPos := idx + pos
			line := lineNumberAtOffset(content, absPos)
			matched := content[absPos : absPos+len(target)]
			hits = append(hits, matchHit{line: line, text: matched})
			idx = absPos + len(target)
		}
	}
	return hits
}

func lineNumberAtOffset(content string, offset int) int {
	line := 1
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

func extractContext(lines []string, lineNum, radius int) []scanner.ContextLine {
	var ctx []scanner.ContextLine
	start := max(lineNum-radius-1, 0)
	end := min(lineNum+radius, len(lines))
	for i := start; i < end; i++ {
		ctx = append(ctx, scanner.ContextLine{
			Line:    i + 1,
			Content: lines[i],
			IsMatch: i+1 == lineNum,
		})
	}
	return ctx
}

func matchesTarget(targetGlobs []string, relPath string) bool {
	if len(targetGlobs) == 0 {
		return true // no filter = match all
	}
	base := filepath.Base(relPath)
	for _, glob := range targetGlobs {
		if matched, _ := filepath.Match(glob, base); matched {
			return true
		}
		if matched, _ := filepath.Match(glob, relPath); matched {
			return true
		}
	}
	return false
}

// isMarkdown returns true if the file path has a markdown extension.
func isMarkdown(relPath string) bool {
	ext := strings.ToLower(filepath.Ext(relPath))
	return ext == ".md" || ext == ".markdown"
}

// BuildCodeBlockMap returns a bool slice where index i is true if lines[i]
// is inside a fenced code block (``` delimited). O(n) single pass.
func BuildCodeBlockMap(lines []string) []bool {
	m := make([]bool, len(lines))
	inBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if inBlock {
				// closing fence — this line is still inside the block
				m[i] = true
				inBlock = false
			} else {
				// opening fence — this line is not inside content
				inBlock = true
			}
			continue
		}
		m[i] = inBlock
	}
	return m
}

// isInCodeBlock checks whether a 1-based line number falls inside a code block.
func isInCodeBlock(cbMap []bool, lineNum int) bool {
	if cbMap == nil || lineNum < 1 || lineNum > len(cbMap) {
		return false
	}
	return cbMap[lineNum-1]
}
