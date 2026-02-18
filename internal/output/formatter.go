package output

import (
	"io"

	"github.com/garagon/aguara/internal/scanner"
)

// Formatter is the interface for outputting scan results.
type Formatter interface {
	Format(w io.Writer, result *scanner.ScanResult) error
}
