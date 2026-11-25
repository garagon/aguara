// Package pattern implements Layer 1 detection: regex and contains matching
// with base64/hex decoding, code block awareness, and exclude patterns.
package pattern

import (
	"context"
	"path/filepath"
	"slices"
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
// A keyword pre-filter skips rules whose required literals don't appear in content.
type Matcher struct {
	allFileRules []*rules.CompiledRule            // rules with targets: [] (match all)
	byExt        map[string][]*rules.CompiledRule // ".ext" -> rules targeting that ext
	acAll        *acSearcher                      // AC automaton for allFileRules contains patterns
	acByExt      map[string]*acSearcher           // AC automaton per extension group
	pf           *prefilter                       // keyword pre-filter for all rules
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
	// Build keyword pre-filter from all rules (regex + contains)
	m.pf = buildPrefilter(compiled)
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
	lowerContent := newLowercaseContent(content)
	lines := target.Lines()

	// Build code block map for markdown files. In ordinary documentation a
	// fenced block is an example, so a match there is reported one severity
	// level lower. In a SKILL.md or agent instruction file the fenced block
	// is what the agent is told to run, so it keeps the rule's severity
	// (InCodeBlock is still reported).
	var cbMap []bool
	if isMarkdownLike(target.RelPath) {
		cbMap = BuildCodeBlockMap(lines)
	}
	downgradeCode := cbMap != nil && !types.IsAgentDirectiveFile(target.RelPath)

	// Collect applicable rules: allFileRules + extension-matched rules
	keys := lookupKeys(target.RelPath)
	applicable := m.rulesForFile(target.RelPath, keys)

	matches, err := m.matchText(ctx, applicable, keys, content, lowerContent, lines, target, nil, true)
	for _, rm := range matches {
		findings = append(findings, directFinding(rm, lines, target, cbMap, downgradeCode))
	}
	if err != nil {
		return findings, err
	}

	// Decode encoded blobs and match the decoded text against the same
	// rules, with the same semantics (see decoder.go).
	decoded, err := m.decodeAndRescan(ctx, target, applicable, keys, cbMap, true)
	findings = append(findings, decoded...)
	return findings, err
}

// matchText runs the applicable rules over one text and returns their
// matches in rule order. With prefilter set, the keyword and contains
// automatons skip rules whose required literals do not occur in the text;
// without it every pattern runs, which tests use as the reference. A
// non-nil keep restricts the matches to hits it accepts: a match_mode: any
// hit must be accepted, and a match_mode: all match needs one accepted hit.
func (m *Matcher) matchText(ctx context.Context, applicable []*rules.CompiledRule, keys []string, content string, lowerContent *lowercaseContent, lines []string, target *scanner.Target, keep func(matchHit) bool, prefilter bool) ([]ruleMatch, error) {
	var candidatePatterns map[string]uint64
	var acHitRules map[string]bool
	if prefilter {
		// Pre-filter: run keyword AC to find which rules could possibly
		// match. Rules whose required literal substrings don't appear are
		// skipped entirely.
		candidatePatterns = m.pf.candidatePatternMasks(lowerContent.text)
		// Secondary pre-filter: AC on contains patterns for exact
		// substring pre-check.
		acHitRules = m.acPrefilter(keys, lowerContent.text)
	}

	var matches []ruleMatch
	for _, rule := range applicable {
		if ctx.Err() != nil {
			return matches, ctx.Err()
		}

		patternMask := ^uint64(0)
		if prefilter {
			// Skip rules whose keywords don't appear in content
			patternMask = candidatePatterns[rule.ID]
			if m.pf.unfiltered[rule.ID] {
				patternMask = ^uint64(0)
			}
			if candidatePatterns != nil && !m.pf.unfiltered[rule.ID] {
				switch rule.MatchMode {
				case rules.MatchAll:
					if patternMask != m.pf.allPatterns[rule.ID] {
						continue
					}
				default:
					if patternMask == 0 {
						continue
					}
				}
			}

			// Skip rules that only have contains patterns and got no AC hits
			if acHitRules != nil && !acHitRules[rule.ID] && isContainsOnly(rule) {
				continue
			}
		}

		switch rule.MatchMode {
		case rules.MatchAny:
			matches = append(matches, m.matchAnySelected(rule, patternMask, content, lowerContent, lines, target, keep)...)
		case rules.MatchAll:
			if rm, ok := m.matchAll(rule, content, lowerContent, lines, keep); ok {
				matches = append(matches, rm)
			}
		}
	}
	return matches, nil
}

// ruleMatch is one reportable match of a rule in a text: the hit of a
// match_mode: any rule, or the hit chosen for each pattern of a
// match_mode: all rule. The first hit is the finding location.
type ruleMatch struct {
	rule *rules.CompiledRule
	hits []matchHit
	conf float64
	all  bool
}

// matchedText is the evidence a finding reports for the match.
func (rm ruleMatch) matchedText() string {
	if !rm.all {
		return rm.hits[0].text
	}
	parts := make([]string, 0, len(rm.hits))
	for _, hit := range rm.hits {
		parts = append(parts, hit.text)
	}
	return strings.Join(parts, " + ")
}

// directFinding reports a match found in the file's own text.
func directFinding(rm ruleMatch, lines []string, target *scanner.Target, cbMap []bool, downgradeCode bool) scanner.Finding {
	rule, line := rm.rule, rm.hits[0].line
	sev := rule.Severity
	inCB := isInCodeBlock(cbMap, line)
	if inCB && downgradeCode {
		sev = types.DowngradeSeverity(sev)
	}
	finding := scanner.Finding{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    sev,
		Category:    rule.Category,
		Description: rule.Description,
		Remediation: rule.Remediation,
		FilePath:    target.RelPath,
		Line:        line,
		MatchedText: rm.matchedText(),
		Context:     types.ExtractContext(lines, line, ctxRadius, ctxRadius),
		Analyzer:    "pattern",
		InCodeBlock: inCB,
		Sensitive:   rule.Sensitive,
		Confidence:  rm.conf,
	}
	if rm.all {
		for _, hit := range rm.hits {
			finding.AddEvidenceRange(hit.line, hit.endLine)
		}
	}
	return finding
}

// acPrefilter runs all AC automatons applicable to this file and returns the set
// of rule IDs that had at least one contains hit. Returns nil if no AC searchers
// are available (meaning no optimization - all rules run). keys are the
// file's rule lookup keys from lookupKeys.
func (m *Matcher) acPrefilter(keys []string, lowerContent string) map[string]bool {
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

	// Search with the extension and file-name specific AC automatons
	for _, key := range keys {
		if ac, ok := m.acByExt[key]; ok {
			for _, match := range ac.findAll(lowerContent) {
				hitRules[match.ruleID] = true
			}
		}
	}

	return hitRules
}

// lookupKeys returns the byExt/acByExt keys that select rules for relPath:
// its lowercased extension, its base name (for literal-file-name targets
// such as "Makefile"), and ".md" for an agent instruction file without a
// Markdown extension (.mdc, .cursorrules, .rules, ...). Those files are
// Markdown documents an agent obeys, so the Markdown-targeted rules,
// prompt injection included, must apply to them.
func lookupKeys(relPath string) []string {
	keys := make([]string, 0, 3)
	ext := strings.ToLower(filepath.Ext(relPath))
	if ext != "" {
		keys = append(keys, ext)
	}
	keys = append(keys, filepath.Base(relPath))
	if ext != ".md" && types.IsAgentInstructionFile(relPath) {
		keys = append(keys, ".md")
	}
	return keys
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
// and literal filename, plus the Markdown rules for an agent instruction
// file (see lookupKeys).
func (m *Matcher) rulesForFile(relPath string, keys []string) []*rules.CompiledRule {
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
	// Markdown rules for an instruction file with another extension. A rule
	// that also targets the file's own extension is already listed.
	if len(keys) > 0 && keys[len(keys)-1] == ".md" && ext != ".md" {
		listed := len(result)
		for _, r := range m.byExt[".md"] {
			if !slices.Contains(result[:listed], r) {
				result = append(result, r)
			}
		}
	}

	// Apply `!`-prefixed exclude targets: a rule scoped broadly (e.g.
	// *.json) can carve out a file owned by a more specific rule
	// (e.g. !package.json). Filter in place; order is preserved.
	kept := result[:0]
	for _, r := range result {
		if len(r.ExcludeTargets) > 0 && fileMatchesAnyGlob(r.ExcludeTargets, relPath, base) {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// fileMatchesAnyGlob reports whether relPath or its basename matches any
// of the globs. Used for `!`-prefixed exclude targets; the simple
// filepath.Match path is enough for the literal-filename and `*.ext`
// exclusions rules use (no `**` support needed here).
func fileMatchesAnyGlob(globs []string, relPath, base string) bool {
	for _, g := range globs {
		if matched, _ := filepath.Match(g, relPath); matched {
			return true
		}
		if matched, _ := filepath.Match(g, base); matched {
			return true
		}
	}
	return false
}

func (m *Matcher) matchAnySelected(rule *rules.CompiledRule, patternMask uint64, content string, lowerContent *lowercaseContent, lines []string, target *scanner.Target, keep func(matchHit) bool) []ruleMatch {
	var matches []ruleMatch
	// Deduplicate findings by line to avoid reporting the same line from
	// multiple patterns. Track which lines already have a finding.
	seenLines := make(map[int]bool)
	// Count how many distinct patterns produced at least one hit (for dynamic confidence)
	hitPatterns := 0
	for patternIndex, pat := range rule.Patterns {
		if patternIndex < 64 && patternMask&(uint64(1)<<patternIndex) == 0 {
			continue
		}
		patternContent := content
		if rule.ID == "SUPPLY_007" && pat.Type == rules.PatternRegex && pat.Value == privilegeWordPattern {
			patternContent = privilegeWordContent(target, content)
		}
		hits := matchPattern(pat, patternContent, lowerContent, lines)
		if len(hits) > 0 {
			hitPatterns++
		}
		for _, hit := range hits {
			if keep != nil && !keep(hit) {
				continue
			}
			if seenLines[hit.line] {
				continue
			}
			if isExcluded(rule.ExcludePatterns, lines, hit) {
				continue
			}
			seenLines[hit.line] = true
			matches = append(matches, ruleMatch{rule: rule, hits: []matchHit{hit}})
		}
	}

	// Dynamic confidence: 0.70 (1 of many patterns) to 0.95 (all patterns hit)
	if len(matches) > 0 && len(rule.Patterns) > 0 {
		conf := 0.70 + 0.25*(float64(hitPatterns)/float64(len(rule.Patterns)))
		for i := range matches {
			matches[i].conf = conf
		}
	}

	return matches
}

func (m *Matcher) matchAll(rule *rules.CompiledRule, content string, lowerContent *lowercaseContent, lines []string, keep func(matchHit) bool) (ruleMatch, bool) {
	// All patterns must have at least one hit that no exclude pattern
	// suppresses. Excludes apply to every contributing hit, as they do in
	// match_mode: any, so a benign form of any pattern's text does not
	// count and an excluded first occurrence does not hide a later one.
	var allHits [][]matchHit
	for _, pat := range rule.Patterns {
		hits := excludeHits(rule.ExcludePatterns, lines, matchPattern(pat, content, lowerContent, lines))
		if len(hits) == 0 {
			return ruleMatch{}, false
		}
		allHits = append(allHits, hits)
	}
	// One contributing hit per pattern: the first hit of each pattern for
	// whole-file rules, or the earliest window of within_lines lines that
	// holds a hit of every pattern. The first pattern's hit is the
	// finding location.
	chosen := make([]matchHit, len(allHits))
	if rule.WithinLines > 0 {
		if !windowHits(allHits, rule.WithinLines, chosen) {
			return ruleMatch{}, false
		}
	} else {
		for i, hits := range allHits {
			chosen[i] = hits[0]
		}
	}
	if keep != nil && !slices.ContainsFunc(chosen, keep) {
		return ruleMatch{}, false
	}
	return ruleMatch{rule: rule, hits: chosen, conf: 0.95, all: true}, true
}

// windowHits looks for the earliest window of at most within consecutive
// lines that contains one hit of every pattern, counting every line a hit
// spans. On success it stores the chosen hit of pattern i in chosen[i] and
// returns true.
//
// Each pattern's hits are ordered and non-overlapping, so their end lines
// increase with their start lines. The sweep keeps one cursor per pattern
// and advances the cursor holding the earliest start until the cursors
// fit in the window or a pattern runs out of hits. When a cursor moves,
// its hit has the earliest start and every other cursor sits on that
// pattern's first hit not passed so far; any window using the passed hit
// would need hits at those cursors or later, which end no earlier, so it
// cannot fit either. No valid window is skipped. O(total hits x patterns).
func windowHits(allHits [][]matchHit, within int, chosen []matchHit) bool {
	cursor := make([]int, len(allHits))
	for {
		minIdx, start, end := 0, 0, 0
		for i, hits := range allHits {
			h := hits[cursor[i]]
			if i == 0 || h.line < start {
				minIdx, start = i, h.line
			}
			end = max(end, h.endLine)
		}
		if end-start+1 <= within {
			for i, hits := range allHits {
				chosen[i] = hits[cursor[i]]
			}
			return true
		}
		cursor[minIdx]++
		if cursor[minIdx] == len(allHits[minIdx]) {
			return false
		}
	}
}

// matchHit is one pattern match. line and endLine are the 1-based first and
// last source lines the match spans (equal for a single-line match); start
// and end are its byte offsets in the matched text; text is the matched
// text, truncated for display.
type matchHit struct {
	line    int
	endLine int
	start   int
	end     int
	text    string
}

// excludeHits drops the hits that an exclude pattern suppresses. The input
// slice is returned unchanged when the rule has no excludes.
func excludeHits(excludes []rules.CompiledExclude, lines []string, hits []matchHit) []matchHit {
	if len(excludes) == 0 || len(hits) == 0 {
		return hits
	}
	kept := make([]matchHit, 0, len(hits))
	for _, hit := range hits {
		if !isExcluded(excludes, lines, hit) {
			kept = append(kept, hit)
		}
	}
	return kept
}

// isExcluded reports whether an exclude pattern suppresses hit. A
// line-scoped exclude (the default) is evaluated against the lines the
// match spans; a context-scoped exclude also inspects the
// rules.ExcludeContextLines lines before the match, which lets a
// documentation heading such as "## Installation" suppress the install
// command listed under it. Each line is evaluated on its own, so `^` and
// `$` in an exclude regex anchor to that line.
func isExcluded(excludes []rules.CompiledExclude, lines []string, hit matchHit) bool {
	if len(excludes) == 0 || hit.line < 1 || hit.line > len(lines) {
		return false
	}
	last := min(max(hit.endLine, hit.line), len(lines))
	for _, ep := range excludes {
		first := hit.line
		if ep.Scope == rules.ExcludeScopeContext {
			first = max(hit.line-rules.ExcludeContextLines, 1)
		}
		for i := first; i <= last; i++ {
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

func matchPattern(pat rules.CompiledPattern, content string, lowerContent *lowercaseContent, lines []string) []matchHit {
	var hits []matchHit
	// Both matchers return ordered source offsets; count each prefix byte once.
	previous, line := 0, 1
	lineAt := func(start int) int {
		line += strings.Count(content[previous:start], "\n")
		previous = start
		return line
	}
	switch pat.Type {
	case rules.PatternRegex:
		if pat.Regex == nil {
			return nil
		}
		locs := pat.Regex.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			line := lineAt(loc[0])
			matched := content[loc[0]:loc[1]]
			endLine := line + strings.Count(matched, "\n")
			if len(matched) > 200 {
				matched = matched[:200] + "..."
			}
			hits = append(hits, matchHit{line: line, endLine: endLine, start: loc[0], end: loc[1], text: matched})
		}
	case rules.PatternContains:
		target := pat.Value // already lowercased during compilation
		if target == "" {
			return nil
		}
		idx := 0
		for {
			pos := strings.Index(lowerContent.text[idx:], target)
			if pos == -1 {
				break
			}
			absPos := idx + pos
			start := lowerContent.originalOffset(absPos)
			end := lowerContent.originalOffset(absPos + len(target))
			line := lineAt(start)
			matched := content[start:end]
			hits = append(hits, matchHit{line: line, endLine: line + strings.Count(matched, "\n"), start: start, end: end, text: matched})
			idx = absPos + len(target)
		}
	}
	return hits
}

// isMarkdownLike reports whether the file is Markdown: it has a Markdown
// extension or is an agent instruction file (Markdown under another name,
// such as .mdc or .cursorrules).
func isMarkdownLike(relPath string) bool {
	ext := strings.ToLower(filepath.Ext(relPath))
	return ext == ".md" || ext == ".markdown" || types.IsAgentInstructionFile(relPath)
}

// BuildCodeBlockMap returns a bool slice where index i is true if lines[i]
// is inside a fenced code block. Fences follow CommonMark: a run of at
// least three backticks or tildes opens a block and may carry an info
// string ("```bash", "~~~ python"), except that a backtick fence's info
// string cannot contain a backtick. Only a run of the same character at
// least as long as the opening run, followed by nothing but whitespace,
// closes the block, so "```python" or a shorter run inside a "````" block
// is content. A block left open runs to the end of the file. Leading
// indentation is ignored so fences nested in list items are recognised.
// The opening fence line is outside the block and the closing fence line
// inside it. O(n) single pass.
func BuildCodeBlockMap(lines []string) []bool {
	m := make([]bool, len(lines))
	var fenceChar byte
	fenceLen := 0 // 0 when outside a block
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if fenceLen == 0 {
			fenceChar, fenceLen = openingFence(trimmed)
			continue
		}
		m[i] = true
		if c, n := fenceRun(trimmed); c == fenceChar && n >= fenceLen && strings.TrimSpace(trimmed[n:]) == "" {
			fenceLen = 0
		}
	}
	return m
}

// fenceRun returns the fence character starting s and how many times it
// repeats, or (0, 0) when s does not start with a backtick or tilde.
func fenceRun(s string) (byte, int) {
	if s == "" || (s[0] != '`' && s[0] != '~') {
		return 0, 0
	}
	n := 1
	for n < len(s) && s[n] == s[0] {
		n++
	}
	return s[0], n
}

// openingFence returns the fence character and length when s opens a
// fenced code block, and (0, 0) otherwise.
func openingFence(s string) (byte, int) {
	c, n := fenceRun(s)
	if n < 3 || (c == '`' && strings.IndexByte(s[n:], '`') >= 0) {
		return 0, 0
	}
	return c, n
}

// isInCodeBlock checks whether a 1-based line number falls inside a code block.
func isInCodeBlock(cbMap []bool, lineNum int) bool {
	if cbMap == nil || lineNum < 1 || lineNum > len(cbMap) {
		return false
	}
	return cbMap[lineNum-1]
}
