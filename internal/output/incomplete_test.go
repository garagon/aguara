package output_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/types"
)

func truncatedIncomplete() *types.ScanResult {
	r := &types.ScanResult{Incomplete: true, FailedOperations: 151, FilesScanned: 3}
	r.Errors = append(r.Errors, types.ScanFailure{Path: "sub", Stage: types.FailureStageDiscover, Reason: types.FailureReasonIO})
	for i := range types.MaxReportedFailures - 1 {
		r.Errors = append(r.Errors, types.ScanFailure{Path: fmt.Sprintf("f%03d.md", i), Stage: types.FailureStageRead, Reason: types.FailureReasonIO})
	}
	return r
}

// The notice states the total and that the JSON list is truncated, and the
// terminal report repeats it in the footer, where a long report ends.
func TestIncompleteNoticeStatesTotalAndTruncation(t *testing.T) {
	r := truncatedIncomplete()
	var term, md bytes.Buffer
	require.NoError(t, (&output.TerminalFormatter{NoColor: true}).Format(&term, r))
	require.NoError(t, (&output.MarkdownFormatter{}).Format(&md, r))
	for name, text := range map[string]string{"terminal": term.String(), "markdown": md.String()} {
		require.Contains(t, text, "SCAN INCOMPLETE: 151 operations failed", name)
		require.Contains(t, text, "sub: could not be listed", name)
		require.Contains(t, text, "+146 more; the JSON report lists the first 100 of 151 failures", name)
	}
	require.Equal(t, 2, strings.Count(term.String(), "SCAN INCOMPLETE"), "header and footer")
	footer := term.String()[strings.LastIndex(term.String(), "files scanned"):]
	require.Contains(t, footer, "SCAN INCOMPLETE")
}
