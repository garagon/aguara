package output

import (
	"fmt"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// maxListedFailures is how many failures text reports name; JSON and
// SARIF carry the full (bounded) list.
const maxListedFailures = 5

// IncompleteSummary is the one-line statement that a scan is incomplete,
// or "" for a complete scan.
func IncompleteSummary(result *scanner.ScanResult) string {
	if !result.Incomplete {
		return ""
	}
	n := result.FailedOperations
	if n == 0 {
		n = len(result.Errors)
	}
	what := "operations"
	if n == 1 {
		what = "operation"
	}
	return fmt.Sprintf("SCAN INCOMPLETE: %d %s failed. The findings are partial, and this is not a clean result.", n, what)
}

// IncompleteDetails names up to maxListedFailures failures, one per line,
// plus a line counting the rest.
func IncompleteDetails(result *scanner.ScanResult) []string {
	if !result.Incomplete {
		return nil
	}
	var lines []string
	for i, f := range result.Errors {
		if i == maxListedFailures {
			break
		}
		lines = append(lines, DescribeFailure(f))
	}
	total := max(result.FailedOperations, len(result.Errors))
	if rest := total - len(lines); rest > 0 {
		lines = append(lines, fmt.Sprintf("+%d more (see errors in the JSON report)", rest))
	}
	return lines
}

// DescribeFailure renders one failure for a human reader.
func DescribeFailure(f types.ScanFailure) string {
	path := TerminalText(f.Path)
	if path == "" {
		path = "scan"
	}
	if f.Analyzer != "" {
		path += " (" + TerminalText(f.Analyzer) + ")"
	}
	return path + ": " + failureReasonText(f)
}

func failureReasonText(f types.ScanFailure) string {
	switch f.Reason {
	case types.FailureReasonBudget:
		return "input exceeds the analyzer's size or structure budget"
	case types.FailureReasonTooLarge:
		return "file exceeds the size limit"
	case types.FailureReasonNotRegular:
		return "file was replaced by a non-regular file during the scan"
	case types.FailureReasonIO:
		if f.Stage == types.FailureStageDiscover {
			return "could not be listed"
		}
		return "could not be read"
	case types.FailureReasonCanceled:
		return "not evaluated: the scan was canceled"
	default:
		return "the analyzer failed"
	}
}
