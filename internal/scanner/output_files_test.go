package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/scanner"
)

// Discovery never returns a file the invocation writes, wherever it sits
// in the tree and however its path is spelled; every other file, including
// other reports, is returned.
func TestDiscoverySkipsOutputFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "README.md", "out/report.json", "other.json", "nested/report.json")
	t.Chdir(dir)

	td := &scanner.TargetDiscovery{OutputFiles: []string{"./out/../out/report.json", filepath.Join(dir, "missing", "x.sarif")}}
	require.Equal(t, []string{"README.md", "nested/report.json", "other.json"}, discovered(t, td, dir))
	require.Len(t, td.SkippedOutputs, 1)

	td = &scanner.TargetDiscovery{OutputFiles: []string{"out/report.json"}}
	targets, err := td.DiscoverPaths(".", []string{"out/report.json", "README.md", "out"})
	require.NoError(t, err)
	require.Equal(t, []string{"README.md"}, relPaths(targets))

	// Without output files nothing changes.
	td = &scanner.TargetDiscovery{}
	require.Len(t, discovered(t, td, dir), 4)
}

func TestScannerReportsSkippedOutputFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "a.md")
	report := filepath.Join(dir, "report.sarif")
	require.NoError(t, os.WriteFile(report, []byte(`{"runs": []}`), 0o644))
	s := scanner.New(1)
	s.SetOutputFiles([]string{report})
	result, err := s.Scan(t.Context(), dir)
	require.NoError(t, err)
	require.Equal(t, 1, result.FilesScanned)
	require.Len(t, result.TargetPolicy.SkippedOutputFiles, 1)
}
