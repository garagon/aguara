package commands

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// captureStderrBytes redirects os.Stderr (where the --insecure-intel
// warning and --fresh fallback notices are written) for the duration of
// fn and returns the captured bytes.
func captureStderrBytes(t *testing.T, fn func()) []byte {
	t.Helper()
	orig := os.Stderr
	tmp, err := os.CreateTemp(t.TempDir(), "stderr-*.txt")
	require.NoError(t, err)
	os.Stderr = tmp
	defer func() {
		os.Stderr = orig
		_ = tmp.Close()
	}()
	fn()
	_ = tmp.Sync()
	data, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	return data
}

// serveBundleBadSignature serves a valid manifest + blob but a corrupted
// signing bundle, so signature verification must fail while the
// manifest/blob content checks would still pass.
func serveBundleBadSignature(t *testing.T) string {
	t.Helper()
	manifest, err := os.ReadFile(bundleFixturePath(t, "valid_manifest.json"))
	require.NoError(t, err)
	blob, err := os.ReadFile(bundleFixturePath(t, "valid_blob.json.gz"))
	require.NoError(t, err)
	badBundle, err := os.ReadFile(bundleFixturePath(t, "valid_bundle.sigstore.json"))
	require.NoError(t, err)
	badBundle = append([]byte{}, badBundle...)
	badBundle[len(badBundle)/2] ^= 0xFF

	mux := http.NewServeMux()
	mux.HandleFunc("/generated_intel.meta.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/generated_intel.meta.json.bundle", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(badBundle) })
	mux.HandleFunc("/generated_intel.json.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(blob) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// runCheckFresh runs `aguara check <dir> --ecosystem npm --fresh ...`
// against baseURL with the store rooted at a temp HOME. --ecosystem npm
// guarantees a non-empty plan so the --fresh fetch actually fires.
// writeBenignNPM seeds a non-compromised node_modules tree so
// `--ecosystem npm` has a target to check (no finding noise), letting the
// test exercise the --fresh fetch path itself.
func writeBenignNPM(t *testing.T, dir string) {
	t.Helper()
	nm := filepath.Join(dir, "node_modules", "leftpad")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nm, "package.json"),
		[]byte(`{"name":"leftpad","version":"1.0.0"}`), 0o644))
}

func runCheckFresh(t *testing.T, dir, baseURL string, extra ...string) error {
	t.Helper()
	writeBenignNPM(t, dir)
	resetFlags()
	prev := intelBundleBaseURL
	intelBundleBaseURL = baseURL
	out := filepath.Join(t.TempDir(), "check.json")
	args := append([]string{"check", dir, "--ecosystem", "npm", "--fresh", "--format", "json", "-o", out}, extra...)
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		intelBundleBaseURL = prev
		resetFlags()
	})
	return rootCmd.Execute()
}

func storeSnapshotPath(home string) string {
	return filepath.Join(home, ".aguara", "intel", "snapshot.json")
}

func TestCheckFreshHappyPathWritesStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, runCheckFresh(t, t.TempDir(), serveSignedBundle(t, false)))
	_, err := os.Stat(storeSnapshotPath(home))
	require.NoError(t, err, "--fresh must write the verified snapshot to the store")
}

func TestCheckFreshTamperedBundleErrorsAndDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	err := runCheckFresh(t, t.TempDir(), serveSignedBundle(t, true))
	require.Error(t, err, "a tampered bundle must fail --fresh")
	_, statErr := os.Stat(storeSnapshotPath(home))
	require.True(t, os.IsNotExist(statErr), "failed verification must not write the cache")
}

func TestCheckFreshAllowStaleUsesVerifiedCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	snapPath := storeSnapshotPath(home)

	// First, a successful --fresh writes a VERIFIED cache (snapshot +
	// provenance marker).
	require.NoError(t, runCheckFresh(t, t.TempDir(), serveSignedBundle(t, false)))
	before, err := os.ReadFile(snapPath)
	require.NoError(t, err)

	// Now --fresh fails (tampered); --allow-stale falls back to the
	// previously verified cache without overwriting it.
	require.NoError(t, runCheckFresh(t, t.TempDir(), serveSignedBundle(t, true), "--allow-stale"))
	after, err := os.ReadFile(snapPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "fallback must not overwrite the verified cache")
}

func TestCheckFreshAllowStaleRejectsUnverifiedLegacyCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Seed a raw snapshot.json with NO provenance marker -- e.g. a cache
	// left by the legacy direct-OSV path or a hand-written file. It must
	// NOT be trusted as "previously verified".
	intelDir := filepath.Join(home, ".aguara", "intel")
	require.NoError(t, os.MkdirAll(intelDir, 0o700))
	require.NoError(t, os.WriteFile(storeSnapshotPath(home),
		[]byte(`{"schema_version":1,"generated_at":"2026-01-01T00:00:00Z","sources":[],"records":[]}`+"\n"), 0o600))

	err := runCheckFresh(t, t.TempDir(), serveSignedBundle(t, true), "--allow-stale")
	require.Error(t, err, "--allow-stale must reject an unverified (markerless) local snapshot")
}

func TestCheckFreshAllowStaleWithoutCacheErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	err := runCheckFresh(t, t.TempDir(), serveSignedBundle(t, true), "--allow-stale")
	require.Error(t, err, "--allow-stale with no cached verified intel must error, not fall back to embedded")
}

func TestCheckFreshInsecureWithoutEnvErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGUARA_INSECURE_INTEL", "") // explicitly unset
	err := runCheckFresh(t, t.TempDir(), serveSignedBundle(t, false), "--insecure-intel")
	require.Error(t, err, "--insecure-intel without AGUARA_INSECURE_INTEL=1 must error")
	require.Contains(t, err.Error(), "AGUARA_INSECURE_INTEL")
}

func TestCheckFreshInsecureWithEnvBypassesBadSignature(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	badSig := serveBundleBadSignature(t)

	// Without --insecure-intel, the bad signature is fatal.
	require.Error(t, runCheckFresh(t, t.TempDir(), badSig),
		"a bad signature must fail --fresh without --insecure-intel")

	// With --insecure-intel + env, signature is skipped (manifest/blob
	// still valid) and a warning is emitted.
	t.Setenv("AGUARA_INSECURE_INTEL", "1")
	var err error
	stderr := captureStderrBytes(t, func() {
		err = runCheckFresh(t, t.TempDir(), badSig, "--insecure-intel")
	})
	require.NoError(t, err, "--insecure-intel + env must accept a valid manifest/blob despite a bad signature")
	require.Contains(t, string(stderr), "WARNING", "--insecure-intel must emit a visible warning")
	require.FileExists(t, storeSnapshotPath(home))
}

func TestAuditFreshTamperedBundleErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// audit derives ecosystems from discovery, so seed a real npm tree
	// to produce a non-empty plan that triggers the --fresh fetch.
	dir := t.TempDir()
	writeCompromisedNPM(t, dir)

	resetFlags()
	prev := intelBundleBaseURL
	intelBundleBaseURL = serveSignedBundle(t, true)
	out := filepath.Join(t.TempDir(), "audit.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"audit", dir, "--fresh", "--format", "json", "-o", out})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		intelBundleBaseURL = prev
		resetFlags()
	})
	require.Error(t, rootCmd.Execute(), "audit --fresh must fail on a tampered bundle (mirrors check)")
	_, statErr := os.Stat(storeSnapshotPath(home))
	require.True(t, os.IsNotExist(statErr), "failed audit --fresh must not write the cache")
}
