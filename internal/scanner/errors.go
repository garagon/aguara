package scanner

import (
	"errors"
	"fmt"
)

// ErrIncompleteScan identifies failures that prevent a successful scan result.
// It is operational status, not a security finding or an enforcement policy.
var ErrIncompleteScan = errors.New("scan incomplete")

type scanFailure struct {
	message string
	cause   error
}

func (e *scanFailure) Error() string        { return e.message }
func (e *scanFailure) Unwrap() error        { return e.cause }
func (e *scanFailure) Is(target error) bool { return target == ErrIncompleteScan }

// IncompleteScanError wraps a pipeline failure with bounded, quoted location
// metadata. Causes may include source secrets: retain them for errors.Is, not
// display. An empty analyzer name identifies a discovery or read failure.
func IncompleteScanError(stage, path, analyzer string, cause error) error {
	message := fmt.Sprintf("%s: %s for %q", ErrIncompleteScan, stage, boundedErrorLabel(path))
	if analyzer != "" {
		message += fmt.Sprintf(" (analyzer %q)", boundedErrorLabel(analyzer))
	}
	return &scanFailure{message: message, cause: cause}
}

func boundedErrorLabel(s string) string {
	const limit = 160
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}
