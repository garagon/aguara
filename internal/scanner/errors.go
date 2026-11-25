package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/garagon/aguara/internal/safefile"
	"github.com/garagon/aguara/internal/types"
)

// ErrIncompleteScan identifies failures that prevent a successful scan result.
// It is operational status, not a security finding or an enforcement policy.
var ErrIncompleteScan = errors.New("scan incomplete")

// ScanFailure re-exports types.ScanFailure.
type ScanFailure = types.ScanFailure

type scanFailure struct {
	message string
	cause   error
	failure types.ScanFailure
}

func (e *scanFailure) Error() string        { return e.message }
func (e *scanFailure) Unwrap() error        { return e.cause }
func (e *scanFailure) Is(target error) bool { return target == ErrIncompleteScan }

// IncompleteScanError wraps a pipeline failure with bounded, quoted location
// metadata. Causes may include source secrets: retain them for errors.Is, not
// display. An empty analyzer name identifies a discovery or read failure.
func IncompleteScanError(stage, path, analyzer string, cause error) error {
	message := fmt.Sprintf("%s: %s for %q", ErrIncompleteScan, stage, boundedErrorLabel(path))
	if path == "" {
		message = fmt.Sprintf("%s: %s", ErrIncompleteScan, stage)
	}
	var sizeErr *fileSizeError
	if errors.As(cause, &sizeErr) {
		// Only this internally constructed numeric diagnostic is safe to
		// display. Arbitrary parser or filesystem causes remain hidden.
		message += fmt.Sprintf(" (file exceeds %d-byte limit)", sizeErr.limit)
	}
	var notRegular *safefile.NotRegularError
	if errors.As(cause, &notRegular) {
		// The file type comes from a fixed list of descriptions.
		message += fmt.Sprintf(" (%s, not a regular file)", safefile.DescribeMode(notRegular.Mode))
	}
	if analyzer != "" {
		message += fmt.Sprintf(" (analyzer %q)", boundedErrorLabel(analyzer))
	}
	return &scanFailure{
		message: message,
		cause:   cause,
		failure: types.ScanFailure{
			Path:     path,
			Stage:    failureStage(stage, analyzer),
			Analyzer: analyzer,
			Reason:   failureReason(cause, analyzer),
		},
	}
}

func failureStage(stage, analyzer string) string {
	switch {
	case analyzer != "":
		return types.FailureStageAnalyze
	case stage == "read target":
		return types.FailureStageRead
	default:
		return types.FailureStageDiscover
	}
}

func failureReason(cause error, analyzer string) string {
	var sizeErr *fileSizeError
	switch {
	case errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded):
		return types.FailureReasonCanceled
	case errors.Is(cause, types.ErrAnalysisBudget):
		return types.FailureReasonBudget
	case errors.As(cause, &sizeErr), errors.Is(cause, safefile.ErrTooLarge):
		return types.FailureReasonTooLarge
	case errors.Is(cause, safefile.ErrNotRegular):
		return types.FailureReasonNotRegular
	case analyzer != "":
		return types.FailureReasonError
	default:
		return types.FailureReasonIO
	}
}

func boundedErrorLabel(s string) string {
	const limit = 160
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}

// IncompleteError is the error of a scan that ran but could not evaluate
// every target with every analyzer: a file could not be read, an analyzer
// failed or exceeded its budget on a file, or the context was canceled.
// It matches ErrIncompleteScan with errors.Is, and also the context's
// error when the scan was canceled or its deadline passed.
//
// Result holds what the scan did find, so a caller that reports or gates
// on findings does not lose them: Result.Incomplete is true, Result.Errors
// lists the failures (Failures is the same list), and Result.Verdict is
// never clean (it is the verdict of the findings present, or flag when
// that would be clean). Other analyzers' findings for a file whose analysis
// failed, and findings an analyzer reported before it failed, are kept.
// The partial result must not be treated as a clean or complete scan.
type IncompleteError struct {
	Result   *ScanResult
	Failures []ScanFailure

	first  error // deterministic diagnostic for the message
	ctxErr error
}

func (e *IncompleteError) Error() string {
	return fmt.Sprintf("%s; %d failed operation(s)", e.first.Error(), e.Result.FailedOperations)
}

// Is reports ErrIncompleteScan.
func (e *IncompleteError) Is(target error) bool { return target == ErrIncompleteScan }

// Unwrap returns the first failure (whose cause errors.Is can inspect)
// and, for a canceled scan, the context's error.
func (e *IncompleteError) Unwrap() []error {
	if e.ctxErr != nil {
		return []error{e.first, e.ctxErr}
	}
	return []error{e.first}
}

// newIncompleteError marks result incomplete and attaches the failures:
// sorted, at most types.MaxReportedFailures listed, all counted. The
// message names one failure chosen deterministically, so it does not
// depend on worker scheduling, and keeps no unbounded list of causes.
func newIncompleteError(result *ScanResult, failures []*scanFailure, ctxErr error) *IncompleteError {
	first := failures[0]
	for _, f := range failures[1:] {
		if f.message < first.message {
			first = f
		}
	}
	list := make([]types.ScanFailure, len(failures))
	for i, f := range failures {
		list[i] = f.failure
	}
	sort.Slice(list, func(i, j int) bool { return failureLess(list[i], list[j]) })
	result.Incomplete = true
	result.FailedOperations = len(list)
	if len(list) > types.MaxReportedFailures {
		list = list[:types.MaxReportedFailures]
	}
	result.Errors = list
	return &IncompleteError{Result: result, Failures: list, first: first, ctxErr: ctxErr}
}

func failureLess(a, b types.ScanFailure) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Stage != b.Stage {
		return a.Stage < b.Stage
	}
	if a.Analyzer != b.Analyzer {
		return a.Analyzer < b.Analyzer
	}
	return a.Reason < b.Reason
}

// asScanFailure returns err as recorded by IncompleteScanError, wrapping
// any other error as a failure of stage at path.
func asScanFailure(err error, stage, path string) *scanFailure {
	var f *scanFailure
	if errors.As(err, &f) {
		return f
	}
	return IncompleteScanError(stage, path, "", err).(*scanFailure)
}
