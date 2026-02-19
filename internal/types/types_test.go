package types_test

import (
	"testing"

	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

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
