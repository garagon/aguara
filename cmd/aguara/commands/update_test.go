package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// makeUpdateResult builds a minimal intel.UpdateResult for the
// writer tests. Pure: no HTTP, no Store, no filesystem beyond
// what each test arranges itself.
func makeUpdateResult(records int, generated time.Time) *intel.UpdateResult {
	return &intel.UpdateResult{
		Snapshot: intel.Snapshot{
			SchemaVersion: intel.CurrentSchemaVersion,
			GeneratedAt:   generated,
			Records:       make([]intel.Record, records),
		},
		PerEcosystem: []intel.EcosystemResult{
			{Ecosystem: intel.EcosystemNPM, RecordsKept: 10, BytesRead: 1024, DownloadedAt: generated},
			{Ecosystem: intel.EcosystemPyPI, RecordsKept: 5, BytesRead: 512, DownloadedAt: generated},
		},
	}
}

// captureStdoutBytes redirects os.Stdout to a temp file for the
// duration of a test and returns the captured bytes. The update
// writers write to os.Stdout directly (not cobra's SetOut, since
// they format machine-readable output), so this is the right
// hook to assert on. Mirrors the helper in status_test.go.
func captureStdoutBytes(t *testing.T, fn func()) []byte {
	t.Helper()
	orig := os.Stdout
	tmp, err := os.CreateTemp(t.TempDir(), "stdout-*.txt")
	require.NoError(t, err)
	os.Stdout = tmp
	defer func() {
		os.Stdout = orig
		_ = tmp.Close()
	}()
	fn()
	_ = tmp.Sync()
	data, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	return data
}

func TestWriteUpdateJSONShape(t *testing.T) {
	// QA on v0.16.0 reported `aguara update --format json` emits
	// human-readable output. PR 3 contract: --format json must
	// emit a stable JSON shape the spec defined ({snapshot_path,
	// records, generated_at, per_ecosystem:[...]}) and nothing
	// else on stdout.
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"
	flagOutput = ""

	res := makeUpdateResult(15, time.Date(2026, time.May, 15, 12, 0, 0, 0, time.UTC))
	snapshotPath := "/home/user/.aguara/intel/snapshot.json"

	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(res, filepath.Dir(snapshotPath)))
	})

	// 1) Must parse as JSON.
	var parsed updateOutput
	require.NoError(t, json.Unmarshal(out, &parsed),
		"--format json must produce parseable JSON, not human text. got: %s", string(out))

	// 2) Field shape matches the spec.
	require.Equal(t, snapshotPath, parsed.SnapshotPath)
	require.Equal(t, 15, parsed.Records)
	require.Equal(t, time.Date(2026, time.May, 15, 12, 0, 0, 0, time.UTC), parsed.GeneratedAt.UTC())
	require.Len(t, parsed.PerEcosystem, 2)
	require.Equal(t, intel.EcosystemNPM, parsed.PerEcosystem[0].Ecosystem)
	require.Equal(t, 10, parsed.PerEcosystem[0].RecordsKept)
	require.Equal(t, int64(1024), parsed.PerEcosystem[0].BytesRead)
	require.Equal(t, intel.EcosystemPyPI, parsed.PerEcosystem[1].Ecosystem)

	// 3) No human-readable lines leaked in. The legacy terminal
	// output starts with "Aguara threat intel updated"; that
	// string must NOT appear in JSON-mode output even as a
	// stray Fprintf.
	require.NotContains(t, string(out), "Aguara threat intel updated",
		"--format json must not emit the human-readable header line")
	require.NotContains(t, string(out), "Written:",
		"--format json must not emit the human-readable 'Written:' line")
}

func TestWriteUpdateJSONEmptyPerEcosystem(t *testing.T) {
	// A run with no ecosystems (unusual but possible if a future
	// configuration filters all of them out) must still emit a
	// VALID JSON document with per_ecosystem as an empty array,
	// not null. Stable shape for typed consumers.
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"

	res := &intel.UpdateResult{
		Snapshot: intel.Snapshot{
			SchemaVersion: intel.CurrentSchemaVersion,
			GeneratedAt:   time.Unix(0, 0).UTC(),
		},
	}
	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(res, "/tmp"))
	})
	require.Contains(t, string(out), `"per_ecosystem": []`,
		"empty per_ecosystem must serialise as [] not null; got: %s", string(out))
}

func TestWriteUpdateJSONToFile(t *testing.T) {
	// --format json combined with -o must redirect the JSON to
	// the file AND leave stdout clean. Critical for automation:
	// callers tee output and pipe stdout; spurious bytes on
	// stdout corrupt their pipeline.
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"
	outFile := filepath.Join(t.TempDir(), "update.json")
	flagOutput = outFile

	res := makeUpdateResult(20, time.Date(2026, time.May, 15, 0, 0, 0, 0, time.UTC))

	stdoutBytes := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(res, "/home/user/.aguara/intel"))
	})

	require.Empty(t, stdoutBytes,
		"--format json -o file must leave stdout empty; bytes leaked: %d", len(stdoutBytes))

	fileBytes, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var parsed updateOutput
	require.NoError(t, json.Unmarshal(fileBytes, &parsed))
	require.Equal(t, 20, parsed.Records)
}

func TestWriteUpdateTerminalDefault(t *testing.T) {
	// Default (no --format) keeps the human-readable output as
	// before. No regression for users who upgrade and were
	// relying on the legacy terminal shape.
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "terminal"

	res := makeUpdateResult(15, time.Unix(0, 0))
	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(res, "/home/user/.aguara/intel"))
	})
	s := string(out)
	require.Contains(t, s, "Aguara threat intel updated")
	require.Contains(t, s, "npm")
	require.Contains(t, s, "PyPI")
	require.Contains(t, s, "Written:")
	// And the terminal output must NOT be valid JSON, so a
	// consumer scripting against --format json sees the
	// difference immediately if they forgot the flag.
	require.False(t, strings.HasPrefix(strings.TrimSpace(s), "{"),
		"terminal default must not start like JSON; got: %s", s)
}

func TestWriteUpdateTerminalRespectsOutputFile(t *testing.T) {
	// -o without --format puts the terminal text in the file
	// (same legacy semantics as scan / check), so users who
	// scripted `aguara update -o file` keep their flow.
	resetFlags()
	t.Cleanup(resetFlags)
	outFile := filepath.Join(t.TempDir(), "update.txt")
	flagOutput = outFile

	res := makeUpdateResult(15, time.Unix(0, 0))
	stdoutBytes := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(res, "/home/user/.aguara/intel"))
	})
	require.Empty(t, stdoutBytes, "with -o, stdout must be empty regardless of format")
	fileBytes, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.Contains(t, string(fileBytes), "Aguara threat intel updated")
}
