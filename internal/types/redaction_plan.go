package types

import (
	"regexp"
	"sort"
	"strings"
)

type redactionLine struct {
	path string
	line int
}

type redactionRange struct {
	first int
	last  int
}

// RedactionPlan retains source locations before filtering can discard their
// findings. It is local to one scan and contains no raw credential values.
// Callers must serialize additions; Apply runs after analysis and scoring.
type RedactionPlan struct {
	lines   map[redactionLine]bool
	keys    map[string][]redactionRange
	matches map[string][]redactionRange
}

// AddFindings records the same context obligations as RedactSensitiveFindings,
// without mutating evidence still needed by scoring or filtering.
func (p *RedactionPlan) AddFindings(findings []Finding) {
	for _, f := range findings {
		if !f.Sensitive && f.Category != "credential-leak" {
			continue
		}
		if p.lines == nil {
			p.lines = make(map[redactionLine]bool)
		}
		if p.matches == nil {
			p.matches = make(map[string][]redactionRange)
		}
		p.matches[f.FilePath] = append(p.matches[f.FilePath], findingRanges(f)...)
		// A decoded header has no trustworthy source end offset. Protect the
		// remainder of that source file rather than expose its possible body.
		if f.Analyzer == "pattern-decoder" && f.Line > 0 {
			if m := privateKeyDelimiter.FindStringSubmatch(f.MatchedText); m != nil && m[1] == "BEGIN" {
				if p.keys == nil {
					p.keys = make(map[string][]redactionRange)
				}
				p.keys[f.FilePath] = append(p.keys[f.FilePath], redactionRange{f.Line, int(^uint(0) >> 1)})
			}
		}
		if f.Line > 0 {
			p.lines[redactionLine{f.FilePath, f.Line}] = true
		}
		for _, cl := range f.Context {
			if f.Sensitive || cl.IsMatch {
				p.lines[redactionLine{f.FilePath, cl.Line}] = true
			}
		}
	}
}

var privateKeyDelimiter = regexp.MustCompile(`-----(BEGIN|END)\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY( BLOCK)?-----`)

// AddContent records complete private-key blocks, including truncated blocks
// through EOF. Delimiters can be embedded in source strings; public keys and
// certificates are not private material. content uses the scanner's normalized
// representation so these lines agree with finding locations.
func (p *RedactionPlan) AddContent(path, content string) {
	if !strings.Contains(content, "PRIVATE KEY") {
		return
	}
	var ranges []redactionRange
	start, line, cursor := 0, 1, 0
	label := ""
	for _, m := range privateKeyDelimiter.FindAllStringSubmatchIndex(content, -1) {
		line += strings.Count(content[cursor:m[0]], "\n")
		endLine := line + strings.Count(content[m[0]:m[1]], "\n")
		kind := ""
		if m[4] >= 0 {
			kind = content[m[4]:m[5]]
		}
		if m[6] >= 0 {
			kind += content[m[6]:m[7]]
		}
		if content[m[2]:m[3]] == "BEGIN" {
			if start == 0 {
				start, label = line, kind
			}
		} else if start != 0 && kind == label {
			ranges = append(ranges, redactionRange{start, endLine})
			start = 0
		}
		line, cursor = endLine, m[1]
	}
	if start != 0 {
		ranges = append(ranges, redactionRange{start, line + strings.Count(content[cursor:], "\n")})
	}
	if len(ranges) > 0 {
		if p.keys == nil {
			p.keys = make(map[string][]redactionRange)
		}
		p.keys[path] = ranges
	}
}

func rangeOverlap(ranges []redactionRange, first, last int) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].last >= first })
	return i < len(ranges) && ranges[i].first <= last
}

func findingRanges(f Finding) []redactionRange {
	if len(f.evidenceRanges) > 0 {
		return f.evidenceRanges
	}
	if f.Line <= 0 {
		return nil
	}
	return []redactionRange{{f.Line, f.Line + strings.Count(f.MatchedText, "\n")}}
}

func normalizeRanges(byPath map[string][]redactionRange) {
	for path, ranges := range byPath {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
		merged := ranges[:0]
		for _, r := range ranges {
			if len(merged) > 0 && r.first <= merged[len(merged)-1].last {
				merged[len(merged)-1].last = max(merged[len(merged)-1].last, r.last)
			} else {
				merged = append(merged, r)
			}
		}
		byPath[path] = merged
	}
}

// Apply sanitizes only after raw-dependent processing. Redacted matches become
// sensitive so a baseline cannot fingerprint a shared placeholder as evidence.
func (p *RedactionPlan) Apply(findings []Finding) {
	normalizeRanges(p.keys)
	normalizeRanges(p.matches)
	for i := range findings {
		f := &findings[i]
		for _, r := range findingRanges(*f) {
			if rangeOverlap(p.keys[f.FilePath], r.first, r.last) || (f.Category != "credential-leak" && rangeOverlap(p.matches[f.FilePath], r.first, r.last)) {
				f.Sensitive = true
				break
			}
		}
		for j := range f.Context {
			cl := &f.Context[j]
			if p.lines[redactionLine{f.FilePath, cl.Line}] || rangeOverlap(p.keys[f.FilePath], cl.Line, cl.Line) || rangeOverlap(p.matches[f.FilePath], cl.Line, cl.Line) {
				cl.Content = RedactedPlaceholder
			}
		}
	}
	RedactSensitiveFindings(findings)
}
