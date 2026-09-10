package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/bundle"
	"github.com/stretchr/testify/require"
)

func TestImportVerifiedBundle(t *testing.T) {
	dir := t.TempDir()
	inputs := map[string]string{
		"generated_intel.meta.json":        "valid_manifest.json",
		"generated_intel.meta.json.bundle": "valid_bundle.sigstore.json",
		"generated_intel.json.gz":          "valid_blob.json.gz",
	}
	for name, fixture := range inputs {
		data, err := os.ReadFile(filepath.Join("..", "..", "internal", "intel", "bundle", "testdata", fixture))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}
	meta, err := os.ReadFile(filepath.Join(dir, "generated_intel.meta.json"))
	require.NoError(t, err)
	signature, err := os.ReadFile(filepath.Join(dir, "generated_intel.meta.json.bundle"))
	require.NoError(t, err)
	blob, err := os.ReadFile(filepath.Join(dir, "generated_intel.json.gz"))
	require.NoError(t, err)
	original, err := bundle.VerifyAndDecode(meta, signature, blob)
	require.NoError(t, err)
	require.NotEqual(t, intel.CurrentOSVAdmissionPolicy, original.AdmissionPolicy, "fixture must exercise migration")
	got, err := importVerifiedBundle(dir)
	require.NoError(t, err)
	require.Equal(t, intel.ApplyOSVAdmissionPolicy(original), got)
	require.Equal(t, original.GeneratedAt, got.GeneratedAt, "refresh must not invent a newer source date")
	require.Equal(t, original.Sources, got.Sources)
	require.NotEmpty(t, got.Records)

	t.Run("tampered blob rejected", func(t *testing.T) {
		changed := append([]byte(nil), blob...)
		changed[len(changed)/2] ^= 0xff
		require.NoError(t, os.WriteFile(filepath.Join(dir, "generated_intel.json.gz"), changed, 0o600))
		got, err := importVerifiedBundle(dir)
		require.Error(t, err)
		require.Equal(t, intel.Snapshot{}, got)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "generated_intel.json.gz"), blob, 0o600))
	})
	t.Run("unsigned input rejected", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "generated_intel.meta.json.bundle"), []byte(`{}`), 0o600))
		got, err := importVerifiedBundle(dir)
		require.Error(t, err)
		require.Equal(t, intel.Snapshot{}, got)
	})
	t.Run("missing input rejected", func(t *testing.T) {
		got, err := importVerifiedBundle(t.TempDir())
		require.Error(t, err)
		require.Equal(t, intel.Snapshot{}, got)
	})
}
