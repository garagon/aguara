package commands

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestReportWritersRejectSymlink(t *testing.T) {
	writers := map[string]func() error{
		"scan":  func() error { return writeOutput(&scanner.ScanResult{}) },
		"check": func() error { return writeCheckJSON(&incident.CheckResult{}) },
		"audit": func() error { return writeAuditJSON(&AuditResult{}) },
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			resetFlags()
			t.Cleanup(resetFlags)
			outside := filepath.Join(t.TempDir(), "untouched")
			require.NoError(t, os.WriteFile(outside, []byte("original"), 0o600))
			flagOutput = filepath.Join(t.TempDir(), "report.json")
			flagFormat = "json"
			if err := os.Symlink(outside, flagOutput); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			err := write()
			data, readErr := os.ReadFile(outside)
			require.NoError(t, readErr)
			require.Equal(t, "original", string(data))
			require.Error(t, err)
		})
	}
}

func TestScanReportFormatsUseSafeFileWriter(t *testing.T) {
	for _, format := range []string{"json", "sarif", "markdown", "md", "terminal"} {
		t.Run(format, func(t *testing.T) {
			resetFlags()
			t.Cleanup(resetFlags)
			flagFormat, flagNoColor = format, true
			dir := t.TempDir()
			flagOutput = filepath.Join(dir, "report")
			result := &scanner.ScanResult{}
			require.NoError(t, writeOutput(result))
			data, err := os.ReadFile(flagOutput)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			require.NoError(t, writeOutput(result))
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1, "no temporary artifacts after replacement")
		})
	}
}

func TestReportEncodingFailurePreservesExistingFile(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"
	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "report")
	require.NoError(t, os.WriteFile(flagOutput, []byte("original"), 0o600))
	err := writeOutput(&scanner.ScanResult{RiskScore: math.NaN()})
	require.Error(t, err)
	data, err := os.ReadFile(flagOutput)
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
