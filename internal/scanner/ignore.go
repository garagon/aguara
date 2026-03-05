package scanner

import (
	"regexp"
	"strings"
)

// ignoreDirective represents a parsed inline ignore comment.
type ignoreDirective struct {
	line    int               // 1-based line where the directive appears
	ruleIDs map[string]bool   // rule IDs to ignore; nil means ignore all
	next    bool              // true = applies to next line, false = applies to same line
}

// commentPrefixes are the tokens that can precede an aguara-ignore directive.
// Covers #, //, --, <!--, and bare (for markdown/txt).
var ignorePattern = regexp.MustCompile(
	`(?:^|#|//|--|<!--)\s*aguara-ignore(?:-next-line)?\s+([A-Z][A-Z0-9_,\s]+?)(?:\s*-->)?\s*$`,
)

var ignoreAllPattern = regexp.MustCompile(
	`(?:^|#|//|--|<!--)\s*aguara-ignore(?:-next-line)?\s*(?:-->)?\s*$`,
)

// parseIgnoreDirectives scans file lines for aguara-ignore comments and returns
// the set of directives found.
func parseIgnoreDirectives(content []byte) []ignoreDirective {
	lines := strings.Split(string(content), "\n")
	var directives []ignoreDirective

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "aguara-ignore") {
			continue
		}

		lineNum := i + 1 // 1-based
		isNext := strings.Contains(trimmed, "aguara-ignore-next-line")

		// Try specific rule IDs first
		if m := ignorePattern.FindStringSubmatch(trimmed); m != nil {
			ids := parseRuleIDs(m[1])
			if len(ids) > 0 {
				directives = append(directives, ignoreDirective{
					line:    lineNum,
					ruleIDs: ids,
					next:    isNext,
				})
				continue
			}
		}

		// Try ignore-all (no rule IDs)
		if ignoreAllPattern.MatchString(trimmed) {
			directives = append(directives, ignoreDirective{
				line:    lineNum,
				ruleIDs: nil, // nil = all rules
				next:    isNext,
			})
		}
	}

	return directives
}

// parseRuleIDs splits a comma-separated list of rule IDs.
func parseRuleIDs(s string) map[string]bool {
	ids := make(map[string]bool)
	for _, part := range strings.Split(s, ",") {
		id := strings.TrimSpace(part)
		if id != "" {
			ids[id] = true
		}
	}
	return ids
}

// buildIgnoreIndex creates a lookup from line number to ignored rule IDs for fast filtering.
// A nil map value means all rules are ignored on that line.
func buildIgnoreIndex(directives []ignoreDirective) map[int]map[string]bool {
	if len(directives) == 0 {
		return nil
	}
	index := make(map[int]map[string]bool)
	for _, d := range directives {
		targetLine := d.line
		if d.next {
			targetLine = d.line + 1
		}

		existing, ok := index[targetLine]
		if ok && existing == nil {
			// Already ignoring all rules on this line
			continue
		}

		if d.ruleIDs == nil {
			// Ignore all rules
			index[targetLine] = nil
			continue
		}

		if existing == nil {
			existing = make(map[string]bool)
			index[targetLine] = existing
		}
		for id := range d.ruleIDs {
			existing[id] = true
		}
	}
	return index
}

// isIgnoredByInline checks whether a finding should be suppressed by an inline directive.
func isIgnoredByInline(index map[int]map[string]bool, line int, ruleID string) bool {
	if index == nil {
		return false
	}
	ids, ok := index[line]
	if !ok {
		return false
	}
	// nil means ignore all rules on this line
	if ids == nil {
		return true
	}
	return ids[ruleID]
}
