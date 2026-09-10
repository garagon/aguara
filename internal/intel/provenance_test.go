package intel_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestStorePlainSaveInvalidatesSameSnapshotVerification(t *testing.T) {
	s := &intel.Store{Dir: t.TempDir()}
	snap := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion}
	require.NoError(t, s.SaveVerified(snap))
	require.NoError(t, s.Save(snap))
	_, err := s.LoadVerified()
	require.Error(t, err, "plain save must not inherit a marker even for identical bytes")
	_, err = s.Load()
	require.NoError(t, err, "unverified snapshot remains inspectable")
	require.NoError(t, s.SaveVerified(snap))
	_, err = s.LoadVerified()
	require.NoError(t, err, "signed refresh restores trust")
}

func TestStoreRejectsLegacyVerificationMarker(t *testing.T) {
	s := &intel.Store{Dir: t.TempDir()}
	require.NoError(t, s.SaveVerified(intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion}))
	path := filepath.Join(s.Dir, "verified.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var marker map[string]any
	require.NoError(t, json.Unmarshal(data, &marker))
	delete(marker, "schema_version")
	data, err = json.Marshal(marker)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err = s.LoadVerified()
	require.Error(t, err, "legacy markers cannot prove signature verification occurred")
	marker["schema_version"] = 999
	data, err = json.Marshal(marker)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err = s.LoadVerified()
	require.Error(t, err, "future markers cannot silently acquire trust")
}

func TestStorePlainSaveAbortsWhenMarkerCannotBeInvalidated(t *testing.T) {
	s := &intel.Store{Dir: t.TempDir()}
	snap := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion}
	require.NoError(t, s.Save(snap))
	path := filepath.Join(s.Dir, "snapshot.json")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	markerPath := filepath.Join(s.Dir, "verified.json")
	require.NoError(t, os.Mkdir(markerPath, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(markerPath, "occupied"), []byte("x"), 0o600))
	snap.Records = []intel.Record{{ID: "different"}}
	require.Error(t, s.Save(snap))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestStoreDifferentUnverifiedSnapshotCannotInheritTrust(t *testing.T) {
	s := &intel.Store{Dir: t.TempDir()}
	snap := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion}
	require.NoError(t, s.SaveVerified(snap))
	snap.Records = []intel.Record{{ID: "different"}}
	require.NoError(t, s.Save(snap))
	_, err := s.LoadVerified()
	require.Error(t, err)
	require.NoFileExists(t, filepath.Join(s.Dir, "verified.json"))
}
