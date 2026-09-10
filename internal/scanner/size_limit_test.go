package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestScanSizeLimitAcrossInputs(t *testing.T) {
	for _, input := range []string{"file", "directory"} {
		t.Run(input, func(t *testing.T) {
			s := scanner.New(1)
			s.SetMaxFileSize(8)
			probe := &completionProbe{}
			s.SetCrossFileAccumulator(probe)
			s.SetStateStore(probe)
			data := []byte("123456789")
			var result *scanner.ScanResult
			var err error
			dir := t.TempDir()
			path := filepath.Join(dir, "input.md")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			if input == "directory" {
				path = dir
			}
			result, err = s.Scan(context.Background(), path)
			require.ErrorIs(t, err, scanner.ErrIncompleteScan)
			require.Contains(t, err.Error(), "8-byte limit")
			require.Nil(t, result)
			require.False(t, probe.finalized)
			require.False(t, probe.saved)
		})
	}
}

func TestDiscoverySizeLimitPreservesExplicitExclusions(t *testing.T) {
	for _, name := range []string{"skip.md", "image.png", "node_modules/large.md", "excluded/large.md"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte("123456789"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.md"), []byte("ok"), 0o600))
			td := scanner.TargetDiscovery{MaxFileSize: 8, IgnorePatterns: []string{"skip.md", "excluded/**"}}
			targets, err := td.Discover(dir)
			require.NoError(t, err)
			require.Len(t, targets, 1)
			require.Equal(t, "ok.md", targets[0].RelPath)
		})
	}
}

func TestTargetSizeLimitExactBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.md")
	require.NoError(t, os.WriteFile(path, []byte("12345678"), 0o600))
	for _, target := range []*scanner.Target{
		{Path: path, MaxFileSize: 8},
		{Content: []byte("12345678"), MaxFileSize: 8},
		{Content: []byte{}, MaxFileSize: 8},
	} {
		require.NoError(t, target.LoadContent())
	}
	target := &scanner.Target{Path: path, MaxFileSize: 8}
	require.NoError(t, target.LoadContent())
	target.MaxFileSize = 7
	require.NoError(t, target.LoadContent(), "preloaded content retains the in-memory contract")
}
