package output

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TerminalText escapes control characters in a data field before styling it.
// It is not for formatted output: layout newlines and trusted ANSI codes must
// be added after this boundary. The source value remains unchanged.
func TerminalText(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", s[0])
		} else if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' ||
			(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			quoted := strconv.QuoteRune(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		} else {
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}
