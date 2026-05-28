package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// makeSnapshot builds a minimal intel.Snapshot for the writer tests, with
// npm + PyPI sources so the ecosystem list populates. Pure: no HTTP, no
// Store, no filesystem.
func makeSnapshot(records int, generated time.Time) intel.Snapshot {
	return intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   generated,
		Sources: []intel.SourceMeta{
			{Name: "osv.dev/npm", Kind: intel.SourceOSV},
			{Name: "osv.dev/pypi", Kind: intel.SourceOSV},
		},
		Records: make([]intel.Record, records),
	}
}

// captureStdoutBytes redirects os.Stdout to a temp file for the duration
// of a test and returns the captured bytes. The update writers write to
// os.Stdout directly (machine-readable output), so this is the right
// hook to assert on.
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
	// --format json must emit a stable JSON shape and nothing else on
	// stdout.
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"
	flagOutput = ""

	snap := makeSnapshot(15, time.Date(2026, time.May, 28, 12, 0, 0, 0, time.UTC))
	storeDir := "/home/user/.aguara/intel"

	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(snap, storeDir))
	})

	var parsed updateOutput
	require.NoError(t, json.Unmarshal(out, &parsed),
		"--format json must produce parseable JSON, not human text. got: %s", string(out))

	require.Equal(t, filepath.Join(storeDir, "snapshot.json"), parsed.SnapshotPath)
	require.Equal(t, 15, parsed.Records)
	require.Equal(t, time.Date(2026, time.May, 28, 12, 0, 0, 0, time.UTC), parsed.GeneratedAt.UTC())
	require.Equal(t, []string{intel.EcosystemNPM, intel.EcosystemPyPI}, parsed.Ecosystems)
	require.True(t, parsed.Verified)
	require.Equal(t, "intel-latest", parsed.Source)

	require.NotContains(t, string(out), "Aguara threat intel updated",
		"--format json must not emit the human-readable header line")
}

func TestWriteUpdateJSONEmptyEcosystems(t *testing.T) {
	// A snapshot with no recognisable sources must still emit valid JSON
	// with ecosystems as [] not null (stable shape for typed consumers).
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"

	snap := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, GeneratedAt: time.Unix(0, 0).UTC()}
	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(snap, "/tmp"))
	})
	require.Contains(t, string(out), `"ecosystems": []`,
		"empty ecosystems must serialise as [] not null; got: %s", string(out))
}

func TestWriteUpdateJSONToFile(t *testing.T) {
	// --format json with -o redirects to the file AND leaves stdout
	// clean (automation pipes stdout).
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "json"
	outFile := filepath.Join(t.TempDir(), "update.json")
	flagOutput = outFile

	snap := makeSnapshot(20, time.Date(2026, time.May, 28, 0, 0, 0, 0, time.UTC))
	stdoutBytes := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(snap, "/home/user/.aguara/intel"))
	})
	require.Empty(t, stdoutBytes, "--format json -o file must leave stdout empty")

	fileBytes, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var parsed updateOutput
	require.NoError(t, json.Unmarshal(fileBytes, &parsed))
	require.Equal(t, 20, parsed.Records)
}

func TestWriteUpdateTerminalDefault(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	flagFormat = "terminal"

	snap := makeSnapshot(15, time.Unix(0, 0))
	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(snap, "/home/user/.aguara/intel"))
	})
	s := string(out)
	require.Contains(t, s, "Aguara threat intel updated")
	require.Contains(t, s, "npm")
	require.Contains(t, s, "PyPI")
	require.Contains(t, s, "written:")
	require.False(t, strings.HasPrefix(strings.TrimSpace(s), "{"),
		"terminal default must not start like JSON; got: %s", s)
}

func TestWriteUpdateTerminalRespectsOutputFile(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	outFile := filepath.Join(t.TempDir(), "update.txt")
	flagOutput = outFile

	snap := makeSnapshot(15, time.Unix(0, 0))
	stdoutBytes := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(snap, "/home/user/.aguara/intel"))
	})
	require.Empty(t, stdoutBytes, "with -o, stdout must be empty regardless of format")
	fileBytes, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.Contains(t, string(fileBytes), "Aguara threat intel updated")
}

// bundleFixtureDir is the bundle package's testdata, which holds a real
// signed manifest + bundle + matching blob from the intel-latest release.
func bundleFixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "internal", "intel", "bundle", "testdata", name)
}

// serveSignedBundle starts an httptest server that serves the three
// intel-latest assets from the bundle package's fixtures, optionally
// tampering with the blob. Returns the base URL.
func serveSignedBundle(t *testing.T, tamperBlob bool) string {
	t.Helper()
	manifest, err := os.ReadFile(bundleFixturePath(t, "valid_manifest.json"))
	require.NoError(t, err)
	bundleBytes, err := os.ReadFile(bundleFixturePath(t, "valid_bundle.sigstore.json"))
	require.NoError(t, err)
	blob, err := os.ReadFile(bundleFixturePath(t, "valid_blob.json.gz"))
	require.NoError(t, err)
	if tamperBlob {
		blob = append([]byte{}, blob...)
		blob[len(blob)/2] ^= 0xFF
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/generated_intel.meta.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/generated_intel.meta.json.bundle", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bundleBytes) })
	mux.HandleFunc("/generated_intel.json.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(blob) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRunUpdateVerifiesAndWritesStore(t *testing.T) {
	// End-to-end: fetch the real signed bundle (served locally), verify
	// it offline against the embedded trusted root, and write the store.
	home := t.TempDir()
	t.Setenv("HOME", home)

	resetFlags()
	t.Cleanup(resetFlags)
	prevURL := intelBundleBaseURL
	intelBundleBaseURL = serveSignedBundle(t, false)
	t.Cleanup(func() { intelBundleBaseURL = prevURL })

	rootCmd.SetArgs([]string{"update", "--format", "json", "-o", filepath.Join(t.TempDir(), "out.json")})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	require.NoError(t, rootCmd.Execute())

	// The verified snapshot must have been written to the store.
	data, err := os.ReadFile(filepath.Join(home, ".aguara", "intel", "snapshot.json"))
	require.NoError(t, err)
	var snap intel.Snapshot
	require.NoError(t, json.Unmarshal(data, &snap))
	require.NotEmpty(t, snap.Records, "verified bundle must populate the store snapshot")
}

func TestRunUpdateRejectsTamperedBundleAndDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	resetFlags()
	t.Cleanup(resetFlags)
	prevURL := intelBundleBaseURL
	intelBundleBaseURL = serveSignedBundle(t, true) // tampered blob
	t.Cleanup(func() { intelBundleBaseURL = prevURL })

	rootCmd.SetArgs([]string{"update", "-o", filepath.Join(t.TempDir(), "out.txt")})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	require.Error(t, rootCmd.Execute(), "a tampered bundle must fail verification")
	// No partial write: the store snapshot must NOT exist.
	_, statErr := os.Stat(filepath.Join(home, ".aguara", "intel", "snapshot.json"))
	require.True(t, os.IsNotExist(statErr), "tampered bundle must not write the cache")
}

func TestAssertOutputNotShadowingStore(t *testing.T) {
	storeDir := t.TempDir()
	snapshotPath := filepath.Join(storeDir, "snapshot.json")

	err := assertOutputNotShadowingStore(snapshotPath, storeDir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "would overwrite")
	require.Contains(t, err.Error(), snapshotPath)

	err = assertOutputNotShadowingStore(snapshotPath+"/./.", storeDir)
	require.Error(t, err)

	err = assertOutputNotShadowingStore("", storeDir)
	require.NoError(t, err)

	err = assertOutputNotShadowingStore(filepath.Join(storeDir, "summary.json"), storeDir)
	require.NoError(t, err)

	t.Chdir(storeDir)
	err = assertOutputNotShadowingStore("snapshot.json", storeDir)
	require.Error(t, err,
		"a relative -o resolving to the snapshot path must collide too")
}

func TestAssertOutputNotShadowingStoreCaseInsensitive(t *testing.T) {
	storeDir := t.TempDir()
	mixedCase := filepath.Join(storeDir, "Snapshot.JSON")
	err := assertOutputNotShadowingStore(mixedCase, storeDir)
	switch runtime.GOOS {
	case "darwin", "windows":
		require.Error(t, err,
			"case-insensitive FS must catch mixed-case -o that resolves to the same file")
		require.Contains(t, err.Error(), "would overwrite")
	default:
		require.NoError(t, err,
			"case-sensitive FS: Snapshot.JSON and snapshot.json are distinct files; guard must not over-reject")
	}
}
