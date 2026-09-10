package pattern

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// lowercaseContent keeps search offsets separate from original evidence offsets.
// The sparse mapping is built only when a contains pattern actually matches.
type lowercaseContent struct {
	text   string
	source string
	mapped bool
	shifts []lowercaseShift
}

type lowercaseShift struct {
	end   int
	delta int
}

func newLowercaseContent(source string) *lowercaseContent {
	return &lowercaseContent{text: strings.ToLower(source), source: source}
}

func (c *lowercaseContent) originalOffset(offset int) int {
	if !c.mapped {
		lowerEnd := 0
		for pos := 0; pos < len(c.source); {
			if c.source[pos] < utf8.RuneSelf {
				pos++
				lowerEnd++
				continue
			}
			r, width := utf8.DecodeRuneInString(c.source[pos:])
			lowerWidth := utf8.RuneLen(unicode.ToLower(r))
			pos += width
			lowerEnd += lowerWidth
			if width != lowerWidth {
				c.shifts = append(c.shifts, lowercaseShift{end: lowerEnd, delta: pos - lowerEnd})
			}
		}
		c.mapped = true
	}
	i := sort.Search(len(c.shifts), func(i int) bool { return c.shifts[i].end > offset })
	if i == 0 {
		return offset
	}
	return offset + c.shifts[i-1].delta
}
