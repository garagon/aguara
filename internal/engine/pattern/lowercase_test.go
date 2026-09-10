package pattern

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzLowercaseOriginalOffsets(f *testing.F) {
	for _, seed := range []string{"plain ASCII", "\u023aMARKER", "\u0130MARKER", "\u023aMARKER\u0130", "\xff\xfeMARKER", "\u212a\n\u023a"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 64<<10 {
			t.Skip()
		}
		view := newLowercaseContent(source)
		lowerPos := 0
		for pos := 0; pos < len(source); {
			_, size := utf8.DecodeRuneInString(source[pos:])
			if got := view.originalOffset(lowerPos); got != pos {
				t.Fatalf("start offset: got %d, want %d", got, pos)
			}
			lowerPos += len(strings.ToLower(source[pos : pos+size]))
			pos += size
			if got := view.originalOffset(lowerPos); got != pos {
				t.Fatalf("end offset: got %d, want %d", got, pos)
			}
		}
		if lowerPos != len(view.text) {
			t.Fatal("per-rune lowercase differs from full string")
		}
	})
}
