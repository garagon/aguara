package output

import (
	"encoding/json"
	"io"

	"github.com/garagon/aguara/internal/scanner"
)

// JSONFormatter outputs findings as a JSON array.
type JSONFormatter struct{}

func (f *JSONFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
