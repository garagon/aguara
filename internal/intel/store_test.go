package intel_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestStoreAtomicSaveLoad(t *testing.T) {
	// Save then Load must round-trip the snapshot. The on-disk
	// file must have 0600 perms so a hostile local process cannot
	// clobber the user's intel between runs.
	dir := t.TempDir()
	s := &intel.Store{Dir: dir}

	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, time.May, 15, 0, 0, 0, 0, time.UTC),
		Sources: []intel.SourceMeta{{
			Name: "test-fixture",
			Kind: intel.SourceManual,
		}},
		Records: []intel.Record{{
			ID:        "FIX-1",
			Ecosystem: intel.EcosystemNPM,
			Name:      "node-ipc",
			Kind:      intel.KindCompromised,
			Versions:  []string{"12.0.1"},
		}},
	}

	require.NoError(t, s.Save(snap))

	got, err := s.Load()
	require.NoError(t, err)
	require.Equal(t, intel.CurrentSchemaVersion, got.SchemaVersion)
	require.Equal(t, snap.GeneratedAt.UTC(), got.GeneratedAt.UTC())
	require.Len(t, got.Records, 1)
	require.Equal(t, "FIX-1", got.Records[0].ID)

	// 0o600: owner-only. We do not require 0o700 on the directory
	// in the test because t.TempDir() on macOS may report 0o755
	// for the system temp prefix.
	info, err := os.Stat(filepath.Join(dir, "snapshot.json"))
	require.NoError(t, err)
	require.Equalf(t, os.FileMode(0o600), info.Mode().Perm(),
		"snapshot file must be owner-only readable; got %v", info.Mode().Perm())
}

func TestStoreLoadMissingFile(t *testing.T) {
	// Load on a Store with no snapshot must return os.ErrNotExist
	// so callers can fall back to the embedded snapshot without
	// having to string-match the error.
	s := &intel.Store{Dir: t.TempDir()}
	_, err := s.Load()
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist),
		"Load on absent file must wrap os.ErrNotExist, got %T: %v", err, err)
}

func TestStoreRejectsOversizedSnapshot(t *testing.T) {
	// A file larger than MaxSnapshotBytes must be rejected with
	// the explicit cap message so an attacker cannot OOM the
	// process by replacing the local snapshot with a giant blob.
	dir := t.TempDir()
	s := &intel.Store{Dir: dir}

	// Write a file that is exactly one byte over the cap.
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "snapshot.json")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	// Fill with `{"schema_version":1,"records":[]}` prefix then
	// pad to MaxSnapshotBytes+1. The JSON shape does not matter
	// because the size cap fires before unmarshal.
	prefix := []byte(`{"schema_version":1,"records":[]}` + "\n")
	_, err = f.Write(prefix)
	require.NoError(t, err)

	pad := make([]byte, intel.MaxSnapshotBytes+1-int64(len(prefix)))
	_, err = f.Write(pad)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = s.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "cap", "oversized snapshot must surface the cap error")
}

func TestStoreRejectsUnknownSchemaVersion(t *testing.T) {
	// A snapshot written by a newer Aguara (schema vN+1) must be
	// rejected explicitly so the older binary does not guess at a
	// shape it does not understand. Same reason go.mod refuses to
	// silently downgrade go directives.
	dir := t.TempDir()
	s := &intel.Store{Dir: dir}

	require.NoError(t, os.MkdirAll(dir, 0o700))
	payload := map[string]any{
		"schema_version": intel.CurrentSchemaVersion + 1,
		"records":        []any{},
	}
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snapshot.json"), data, 0o600))

	_, err = s.Load()
	require.Error(t, err)
	require.True(t,
		strings.Contains(err.Error(), "schema") || strings.Contains(err.Error(), "upgrade"),
		"unknown-schema error must mention schema/upgrade, got: %v", err)
}

func TestStoreStatusWithoutSnapshot(t *testing.T) {
	// Status on an empty store reports HasSnapshot=false and
	// must NOT error out. `aguara status` calls this on every
	// invocation and a "no cache yet" condition is normal.
	s := &intel.Store{Dir: t.TempDir()}
	st := s.Status()
	require.False(t, st.HasSnapshot)
	require.NotEmpty(t, st.Path)
	require.Empty(t, st.LastUpdateErr)
}

func TestStoreStatusWithSnapshot(t *testing.T) {
	s := &intel.Store{Dir: t.TempDir()}
	require.NoError(t, s.Save(intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, time.May, 15, 12, 0, 0, 0, time.UTC),
		Records: []intel.Record{
			{ID: "A", Ecosystem: "npm", Name: "x", Versions: []string{"1"}},
			{ID: "B", Ecosystem: "npm", Name: "y", Versions: []string{"2"}},
		},
	}))
	st := s.Status()
	require.True(t, st.HasSnapshot)
	require.Equal(t, 2, st.RecordCount)
	require.False(t, st.GeneratedAt.IsZero())
}

func TestStoreSaveRefusesFutureSchema(t *testing.T) {
	// Save must mirror Load and refuse to write a schema the
	// current binary does not own. Prevents a misconfigured
	// caller from poisoning the cache with a v2 file the rest
	// of this binary cannot read.
	s := &intel.Store{Dir: t.TempDir()}
	err := s.Save(intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion + 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing")
}

func TestStoreSaveOverwritesAtomically(t *testing.T) {
	// Save twice must replace the first snapshot, leaving no
	// orphan temp file. A surviving `.snapshot-*.json` would
	// indicate a partial write the user has to clean up by hand.
	dir := t.TempDir()
	s := &intel.Store{Dir: dir}

	require.NoError(t, s.Save(intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records:       []intel.Record{{ID: "first", Ecosystem: "npm", Name: "x", Versions: []string{"1"}}},
	}))
	require.NoError(t, s.Save(intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records:       []intel.Record{{ID: "second", Ecosystem: "npm", Name: "x", Versions: []string{"2"}}},
	}))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".snapshot-", "orphan temp file from atomic save: %s", e.Name())
	}

	got, err := s.Load()
	require.NoError(t, err)
	require.Len(t, got.Records, 1)
	require.Equal(t, "second", got.Records[0].ID)
}
