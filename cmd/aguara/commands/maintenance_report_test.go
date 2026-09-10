package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/incident"
	"github.com/stretchr/testify/require"
)

func TestMaintenanceReportsReplaceFiles(t *testing.T) {
	for name, write := range map[string]func() error{
		"clean":           func() error { return writeCleanJSON(&incident.CleanResult{}) },
		"update-json":     func() error { return writeUpdateJSON(updateOutput{}) },
		"update-terminal": func() error { return writeUpdateTerminal(updateOutput{}) },
	} {
		t.Run(name, func(t *testing.T) {
			resetFlags()
			t.Cleanup(resetFlags)
			dir := t.TempDir()
			flagOutput = filepath.Join(dir, "report")
			want := captureStdoutBytes(t, func() {
				flagOutput = ""
				require.NoError(t, write())
			})
			flagOutput = filepath.Join(dir, "report")
			require.NoError(t, os.WriteFile(flagOutput, []byte("old report"), 0o600))
			linked := filepath.Join(t.TempDir(), "linked-report")
			linkErr := os.Link(flagOutput, linked)
			if runtime.GOOS != "windows" {
				require.NoError(t, linkErr)
			} else if linkErr != nil {
				t.Logf("hardlink check unavailable: %v", linkErr)
			}
			stdout := captureStdoutBytes(t, func() { require.NoError(t, write()) })
			require.Empty(t, stdout)
			got, err := os.ReadFile(flagOutput)
			require.NoError(t, err)
			require.Equal(t, want, got)
			if linkErr == nil {
				old, err := os.ReadFile(linked)
				require.NoError(t, err)
				require.Equal(t, "old report", string(old))
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(flagOutput)
				require.NoError(t, err)
				require.Zero(t, info.Mode().Perm()&0o077)
			}
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

func TestMaintenanceReportEncodingFailurePreservesFile(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "report")
	require.NoError(t, os.WriteFile(flagOutput, []byte("original"), 0o600))
	err := writeUpdateJSON(updateOutput{GeneratedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)})
	require.Error(t, err)
	data, err := os.ReadFile(flagOutput)
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
