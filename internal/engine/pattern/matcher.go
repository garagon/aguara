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

// ctxRadius is the number of context lines before and after a match.
const ctxRadius = 3


// Matcher implements the Analyzer interface using compiled pattern rules.
// Rules are pre-grouped by target extension for fast lookup.
// Contains patterns use Aho-Corasick multi-pattern matching for O(n+m) search.
type Matcher struct {
	allFileRules []*rules.CompiledRule            // rules with targets: [] (match all)
	byExt        map[string][]*rules.CompiledRule // ".ext" -> rules targeting that ext
	acAll        *acSearcher                      // AC automaton for allFileRules contains patterns
	acByExt      map[string]*acSearcher           // AC automaton per extension group
}

// NewMatcher creates a new pattern matcher with the given compiled rules.
// Rules are pre-grouped by target extension to skip inapplicable rules per file.
func NewMatcher(compiled []*rules.CompiledRule) *Matcher {
	m := &Matcher{
		byExt:   make(map[string][]*rules.CompiledRule),
		acByExt: make(map[string]*acSearcher),
	}
	for _, rule := range compiled {
		if len(rule.Targets) == 0 {
			m.allFileRules = append(m.allFileRules, rule)
			continue
		}
		for _, glob := range rule.Targets {
			ext := globToExt(glob)
			m.byExt[ext] = append(m.byExt[ext], rule)
		}
	}
	// Build Aho-Corasick automatons for contains patterns
	m.acAll = buildACSearcher(m.allFileRules)
	for ext, extRules := range m.byExt {
		if ac := buildACSearcher(extRules); ac != nil {
			m.acByExt[ext] = ac
		}
	}
	return m
}

// globToExt extracts a lookup key from a target glob.
// "*.md" -> ".md", "*.json" -> ".json", "Makefile" -> "Makefile"
func globToExt(glob string) string {
	if strings.HasPrefix(glob, "*.") {
		return glob[1:] // "*.md" -> ".md"
	}
	return glob // literal filename like "Makefile"
}

func (m *Matcher) Name() string { return "pattern" }

func (m *Matcher) Analyze(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	content := target.StringContent()
	lowerContent := strings.ToLower(content)
	lines := target.Lines()

	// Build code block map for markdown files
	var cbMap []bool
	if isMarkdown(target.RelPath) {
		cbMap = BuildCodeBlockMap(lines)
	}

	// Collect applicable rules: allFileRules + extension-matched rules
	applicable := m.rulesForFile(target.RelPath)

	// Pre-filter: run Aho-Corasick to find which rules have contains matches.
	// Rules with no contains hits and only contains patterns can be skipped entirely.
	acHitRules := m.acPrefilter(target.RelPath, lowerContent)

	for _, rule := range applicable {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}

		// Skip rules that only have contains patterns and got no AC hits
		if acHitRules != nil && !acHitRules[rule.ID] && isContainsOnly(rule) {
			continue
		}

		switch rule.MatchMode {
		case rules.MatchAny:
			findings = append(findings, m.matchAny(rule, content, lowerContent, lines, target, cbMap)...)
		case rules.MatchAll:
			findings = append(findings, m.matchAll(rule, content, lowerContent, lines, target, cbMap)...)
		}
	}

	// Phase 4: decode base64/hex blobs and re-scan with all-target rules only.
	// Extension-specific rules are irrelevant for decoded content (no file context).
	findings = append(findings, DecodeAndRescan(target, m.allFileRules, cbMap)...)

	return findings, nil
}

// acPrefilter runs all AC automatons applicable to this file and returns the set
// of rule IDs that had at least one contains hit. Returns nil if no AC searchers
// are available (meaning no optimization - all rules run).
func (m *Matcher) acPrefilter(relPath, lowerContent string) map[string]bool {
	if m.acAll == nil && len(m.acByExt) == 0 {
		return nil
	}

	hitRules := make(map[string]bool)

	// Search with the all-files AC automaton
	if m.acAll != nil {
		for _, match := range m.acAll.findAll(lowerContent) {
			hitRules[match.ruleID] = true
		}
	}

	// Search with extension-specific AC automatons
	ext := strings.ToLower(filepath.Ext(relPath))
	if ext != "" {
		if ac, ok := m.acByExt[ext]; ok {
			for _, match := range ac.findAll(lowerContent) {
				hitRules[match.ruleID] = true
			}
		}
	}
	base := filepath.Base(relPath)
	if ac, ok := m.acByExt[base]; ok {
		for _, match := range ac.findAll(lowerContent) {
			hitRules[match.ruleID] = true
		}
	}

	return hitRules
}

// isContainsOnly returns true if the rule has only contains patterns (no regex).
func isContainsOnly(rule *rules.CompiledRule) bool {
	for _, pat := range rule.Patterns {
		if pat.Type != rules.PatternContains {
			return false
		}
	}
	return true
}

// rulesForFile returns the rules applicable to a given file path.
// Combines allFileRules (targets: []) with rules matching the file's extension
// and literal filename.
func (m *Matcher) rulesForFile(relPath string) []*rules.CompiledRule {
	result := make([]*rules.CompiledRule, 0, len(m.allFileRules)+20)
	result = append(result, m.allFileRules...)

	ext := strings.ToLower(filepath.Ext(relPath))
	if ext != "" {
		result = append(result, m.byExt[ext]...)
	}
	// Also check literal filename matches (e.g. "Makefile", "setup.py")
	base := filepath.Base(relPath)
	if rules, ok := m.byExt[base]; ok {
		result = append(result, rules...)
	}
	return result
}

func (m *Matcher) matchAny(rule *rules.CompiledRule, content, lowerContent string, lines []string, target *scanner.Target, cbMap []bool) []scanner.Finding {
	var findings []scanner.Finding
	// Deduplicate findings by line to avoid reporting the same line from
	// multiple patterns. Track which lines already have a finding.
	seenLines := make(map[int]bool)
	// Count how many distinct patterns produced at least one hit (for dynamic confidence)
	hitPatterns := 0
	for _, pat := range rule.Patterns {
		hits := matchPattern(pat, content, lowerContent, lines)
		if len(hits) > 0 {
			hitPatterns++
		}
		for _, hit := range hits {
			if seenLines[hit.line] {
				continue
			}
			if isExcluded(rule.ExcludePatterns, lines, hit.line) {
				continue
			}
			sev := rule.Severity
			inCB := isInCodeBlock(cbMap, hit.line)
			if inCB {
				sev = types.DowngradeSeverity(sev)
			}
			seenLines[hit.line] = true
			findings = append(findings, scanner.Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    sev,
				Category:    rule.Category,
				Description: rule.Description,
				Remediation: rule.Remediation,
				FilePath:    target.RelPath,
				Line:        hit.line,
				MatchedText: hit.text,
				Context:     types.ExtractContext(lines, hit.line, ctxRadius, ctxRadius),
				Analyzer:    "pattern",
				InCodeBlock: inCB,
				Confidence:  0.85, // placeholder, updated below
			})
		}
	}

	// Dynamic confidence: 0.70 (1 of many patterns) to 0.95 (all patterns hit)
	if len(findings) > 0 && len(rule.Patterns) > 0 {
		conf := 0.70 + 0.25*(float64(hitPatterns)/float64(len(rule.Patterns)))
		for i := range findings {
			findings[i].Confidence = conf
		}
	}

	return findings
}

func (m *Matcher) matchAll(rule *rules.CompiledRule, content, lowerContent string, lines []string, target *scanner.Target, cbMap []bool) []scanner.Finding {
	// All patterns must have at least one hit
	var allHits [][]matchHit
	for _, pat := range rule.Patterns {
		hits := matchPattern(pat, content, lowerContent, lines)
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
		Remediation: rule.Remediation,
		FilePath:    target.RelPath,
		Line:        firstHit.line,
		MatchedText: strings.Join(matchedParts, " + "),
		Context:     types.ExtractContext(lines, firstHit.line, ctxRadius, ctxRadius),
		Analyzer:    "pattern",
		InCodeBlock: inCB,
		Confidence:  0.95,
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

func matchPattern(pat rules.CompiledPattern, content, lowerContent string, lines []string) []matchHit {
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
		target := pat.Value // already lowercased during compilation
		idx := 0
		for {
			pos := strings.Index(lowerContent[idx:], target)
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
