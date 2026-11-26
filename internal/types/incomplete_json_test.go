package types_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/types"
)

// A consumer that decodes a report into the library type must not read an
// incomplete scan as complete.
func TestScanResultJSONRoundTripKeepsCompleteness(t *testing.T) {
	incomplete := types.ScanResult{
		Incomplete:       true,
		Errors:           []types.ScanFailure{{Path: "a.md", Stage: types.FailureStageRead, Reason: types.FailureReasonIO}},
		FailedOperations: 3,
		Duration:         1500 * time.Millisecond,
	}
	data, err := json.Marshal(incomplete)
	require.NoError(t, err)
	var decoded types.ScanResult
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.True(t, decoded.Incomplete)
	require.Equal(t, incomplete.Errors, decoded.Errors)
	require.Equal(t, 3, decoded.FailedOperations)
	require.Equal(t, 1500*time.Millisecond, decoded.Duration)

	data, err = json.Marshal(types.ScanResult{})
	require.NoError(t, err)
	decoded = types.ScanResult{Incomplete: true}
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.False(t, decoded.Incomplete)

	// A report from an older version has no "complete" field.
	decoded = types.ScanResult{}
	require.NoError(t, json.Unmarshal([]byte(`{"findings":[],"files_scanned":1}`), &decoded))
	require.False(t, decoded.Incomplete)
	require.Equal(t, 1, decoded.FilesScanned)
}
