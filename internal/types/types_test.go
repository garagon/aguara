package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestScanResultMarshalJSON_NilFindingsEmitsEmptyArray(t *testing.T) {
	// Any ScanResult producer that leaves Findings nil (the aggregate
	// path in runAutoScan, a library consumer constructing a result
	// directly) must still serialize as `"findings": []` so machine
	// consumers do not have to handle null specially.
	r := types.ScanResult{
		FilesScanned: 0,
		RulesLoaded:  189,
	}
	out, err := json.Marshal(r)
	require.NoError(t, err)
	js := string(out)
	require.NotContains(t, js, `"findings":null`,
		"nil Findings must not serialize as null, got: %s", js)
	require.True(t,
		strings.Contains(js, `"findings":[]`),
		"expected findings: [] in marshaled output, got: %s", js)
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  types.Severity
		want string
	}{
		{types.SeverityCritical, "CRITICAL"},
		{types.SeverityHigh, "HIGH"},
		{types.SeverityMedium, "MEDIUM"},
		{types.SeverityLow, "LOW"},
		{types.SeverityInfo, "INFO"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, tt.sev.String())
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  types.Severity
		err   bool
	}{
		{"CRITICAL", types.SeverityCritical, false},
		{"high", types.SeverityHigh, false},
		{"Medium", types.SeverityMedium, false},
		{"  low  ", types.SeverityLow, false},
		{"INFO", types.SeverityInfo, false},
		{"invalid", types.SeverityInfo, true},
	}
	for _, tt := range tests {
		got, err := types.ParseSeverity(tt.input)
		if tt.err {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		}
	}
}

func TestVerdictString(t *testing.T) {
	tests := []struct {
		v    types.Verdict
		want string
	}{
		{types.VerdictClean, "clean"},
		{types.VerdictFlag, "flag"},
		{types.VerdictBlock, "block"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, tt.v.String())
	}
}

func TestScanProfileConstants(t *testing.T) {
	// Ensure profiles have correct ordering
	require.Equal(t, types.ScanProfile(0), types.ProfileStrict)
	require.Equal(t, types.ScanProfile(1), types.ProfileContentAware)
	require.Equal(t, types.ScanProfile(2), types.ProfileMinimal)
}

func TestDowngradeSeverity(t *testing.T) {
	tests := []struct {
		input types.Severity
		want  types.Severity
	}{
		{types.SeverityCritical, types.SeverityHigh},
		{types.SeverityHigh, types.SeverityMedium},
		{types.SeverityMedium, types.SeverityLow},
		{types.SeverityLow, types.SeverityLow},
		{types.SeverityInfo, types.SeverityInfo},
	}
	for _, tt := range tests {
		got := types.DowngradeSeverity(tt.input)
		require.Equal(t, tt.want, got, "DowngradeSeverity(%s)", tt.input)
	}
}
