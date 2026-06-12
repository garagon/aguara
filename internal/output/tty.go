package output

import (
	"io"
	"os"

	"golang.org/x/term"
)

// IsTerminal reports whether w is attached to an interactive terminal.
// Non-file writers (buffers, pipes wrapped in io.Writer) are never
// terminals.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// DetectWidth returns the rendering width for w when it is an
// interactive terminal, clamped to [40, 100] so narrow terminals keep
// separators on one line and wide ones do not stretch section rules
// across the whole screen. Returns 0 (use the caller's default) when
// w is not a terminal or its size cannot be read.
func DetectWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil || cols <= 0 {
		return 0
	}
	return min(max(cols, 40), 100)
}
