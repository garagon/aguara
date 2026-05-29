package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Store reads and writes a Snapshot to a directory on disk. It is
// the runtime cache for `aguara update`; the embedded snapshot
// shipped with the binary lives in code and does not pass through
// Store.
//
// All on-disk paths are derived from Dir so callers can point Store
// at a temp directory in tests without touching $HOME.
type Store struct {
	Dir string
}

// Default file names inside the Store directory. Documented so
// external tooling (operators inspecting the cache, support
// scripts) can find them without reading the Go code. A future
// status.json (recording last update attempt + error) will land
// in the runtime-update PR; the current Store keeps state in-memory.
const snapshotFileName = "snapshot.json"

// verifiedMarkerFileName is the provenance marker written next to the
// snapshot by SaveVerified. Its presence + matching digest is what marks
// a local snapshot as "previously verified by a signed bundle".
const verifiedMarkerFileName = "verified.json"

// verifiedMarker binds a local snapshot to a successful signature
// verification by recording the SHA-256 of the exact snapshot bytes.
type verifiedMarker struct {
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// MaxSnapshotBytes caps the size of any snapshot Store will Load
// from disk. Snapshots are user-trusted data after `aguara update`
// downloads them, but a corrupted or attacker-tampered file should
// not be able to OOM the process. 64 MiB is well above any
// foreseeable malicious-package-only OSV slice.
const MaxSnapshotBytes int64 = 64 * 1024 * 1024

// Status is a small human/machine-readable summary of the Store's
// state. Aguara status reads this so it can answer "is local intel
// fresh?" without having to deserialise the full snapshot.
type Status struct {
	HasSnapshot    bool      `json:"has_snapshot"`
	Path           string    `json:"path"`
	GeneratedAt    time.Time `json:"generated_at,omitempty"`
	RecordCount    int       `json:"record_count,omitempty"`
	LastUpdateErr  string    `json:"last_update_err,omitempty"`
	LastUpdateTime time.Time `json:"last_update_time,omitempty"`
}

// DefaultStore returns a Store rooted at ~/.aguara/intel.
//
// The directory is NOT created here -- creation is deferred to
// Save() so a read-only `aguara check` against the embedded
// snapshot never has to touch $HOME. Callers that need the
// directory eagerly (e.g. the update command before writing) can
// call Store.ensureDir.
func DefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("intel store: resolve home: %w", err)
	}
	return &Store{Dir: filepath.Join(home, ".aguara", "intel")}, nil
}

// snapshotPath returns the path to the on-disk snapshot file.
func (s *Store) snapshotPath() string { return filepath.Join(s.Dir, snapshotFileName) }

// verifiedMarkerPath returns the path to the provenance marker.
func (s *Store) verifiedMarkerPath() string { return filepath.Join(s.Dir, verifiedMarkerFileName) }

// ensureDir creates s.Dir with permissions readable+writable only
// by the current user, never by group or world. The snapshot is
// not a secret, but a 0o755 cache is one more place a hostile
// process could clobber the user's intel.
func (s *Store) ensureDir() error {
	return os.MkdirAll(s.Dir, 0o700)
}

// Load reads the snapshot from disk and returns it. Returns
// (nil, os.ErrNotExist) when no snapshot has been written yet; the
// caller should fall back to the embedded snapshot rather than
// erroring out.
//
// Load enforces the MaxSnapshotBytes cap by using io.LimitReader,
// so a malicious or corrupted file cannot cause unbounded
// allocation. The schema version is checked; unknown versions
// produce an error so a newer Aguara binary writing a v2 snapshot
// does not get silently misread by an older binary.
func (s *Store) Load() (*Snapshot, error) {
	f, err := os.Open(s.snapshotPath())
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// LimitReader caps how much we will accept. +1 byte so we can
	// distinguish "exactly the cap" from "exceeded the cap".
	limited := io.LimitReader(f, MaxSnapshotBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("intel store: read %s: %w", s.snapshotPath(), err)
	}
	if int64(len(data)) > MaxSnapshotBytes {
		return nil, fmt.Errorf("intel store: snapshot exceeds %d bytes (cap)", MaxSnapshotBytes)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("intel store: decode %s: %w", s.snapshotPath(), err)
	}
	if snap.SchemaVersion == 0 {
		// Legacy/test-fixture snapshots may omit the field; treat
		// as v1 since that is the only shape this binary writes.
		snap.SchemaVersion = CurrentSchemaVersion
	}
	if snap.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("intel store: snapshot schema v%d is newer than this binary (v%d); upgrade aguara",
			snap.SchemaVersion, CurrentSchemaVersion)
	}
	return &snap, nil
}

// Save persists snap to disk atomically: it writes to a temp file
// in the same directory, fsyncs it, then renames over the existing
// snapshot. A concurrent Load can only ever see the previous
// snapshot or the new one, never a half-written file.
//
// Save validates snap by re-marshalling the JSON before writing so
// a struct that cannot serialise (e.g. an exotic time) errors out
// before the on-disk file is touched.
func (s *Store) Save(snap Snapshot) error {
	data, err := s.marshalForSave(snap)
	if err != nil {
		return err
	}
	if err := s.ensureDir(); err != nil {
		return fmt.Errorf("intel store: mkdir: %w", err)
	}
	return s.atomicWrite(s.snapshotPath(), data)
}

// SaveVerified persists snap AND a provenance marker (verified.json)
// recording that this snapshot came from a signature-verified advisory
// bundle. The marker binds to the snapshot by SHA-256 of the exact bytes
// written, so a later hand-edit or swap of snapshot.json invalidates it.
// LoadVerified (and therefore --allow-stale) trusts a local snapshot only
// when this marker is present and matches; a legacy or hand-written
// snapshot.json with no marker is treated as unverified.
//
// The snapshot is written first, then the marker, so a torn write leaves
// at worst a snapshot with a missing/mismatched marker -- which reads as
// "unverified", the safe outcome.
func (s *Store) SaveVerified(snap Snapshot) error {
	data, err := s.marshalForSave(snap)
	if err != nil {
		return err
	}
	if err := s.ensureDir(); err != nil {
		return fmt.Errorf("intel store: mkdir: %w", err)
	}
	if err := s.atomicWrite(s.snapshotPath(), data); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	marker := verifiedMarker{
		SnapshotSHA256: hex.EncodeToString(sum[:]),
		VerifiedAt:     time.Now().UTC(),
	}
	markerData, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("intel store: marshal verified marker: %w", err)
	}
	return s.atomicWrite(s.verifiedMarkerPath(), markerData)
}

// marshalForSave validates the schema and serialises snap, applying the
// size cap. Shared by Save and SaveVerified so both write identical bytes.
func (s *Store) marshalForSave(snap Snapshot) ([]byte, error) {
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = CurrentSchemaVersion
	}
	if snap.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("intel store: refusing to save schema v%d (this binary writes v%d)",
			snap.SchemaVersion, CurrentSchemaVersion)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("intel store: marshal: %w", err)
	}
	if int64(len(data)) > MaxSnapshotBytes {
		return nil, fmt.Errorf("intel store: snapshot serialises to %d bytes, exceeds %d cap",
			len(data), MaxSnapshotBytes)
	}
	return data, nil
}

// atomicWrite writes data to dst via a temp file in the same directory,
// fsynced and chmod 0600, then renamed over dst. A concurrent reader sees
// only the old or the new file, never a half-written one.
func (s *Store) atomicWrite(dst string, data []byte) error {
	tmp, err := os.CreateTemp(s.Dir, ".intel-*.tmp")
	if err != nil {
		return fmt.Errorf("intel store: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel store: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel store: fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel store: close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel store: chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel store: rename %s -> %s: %w", tmpName, dst, err)
	}
	return nil
}

// LoadVerified loads the snapshot ONLY if the provenance marker is present
// and matches it byte-for-byte. It returns os.ErrNotExist when there is no
// snapshot or no marker (so callers can treat "no verified intel" the same
// as "no intel"), and a distinct error when a marker exists but does not
// match the snapshot (tamper / partial write).
func (s *Store) LoadVerified() (*Snapshot, error) {
	data, err := os.ReadFile(s.snapshotPath())
	if err != nil {
		return nil, err // includes os.ErrNotExist
	}
	if int64(len(data)) > MaxSnapshotBytes {
		return nil, fmt.Errorf("intel store: snapshot exceeds %d bytes (cap)", MaxSnapshotBytes)
	}
	markerData, err := os.ReadFile(s.verifiedMarkerPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Snapshot present but no provenance marker: treat as
			// not-verified (legacy / hand-written cache).
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("intel store: read verified marker: %w", err)
	}
	var marker verifiedMarker
	if err := json.Unmarshal(markerData, &marker); err != nil {
		return nil, fmt.Errorf("intel store: decode verified marker: %w", err)
	}
	sum := sha256.Sum256(data)
	if marker.SnapshotSHA256 != hex.EncodeToString(sum[:]) {
		return nil, fmt.Errorf("intel store: snapshot does not match its verified marker (cache was modified after verification)")
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("intel store: decode %s: %w", s.snapshotPath(), err)
	}
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = CurrentSchemaVersion
	}
	if snap.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("intel store: snapshot schema v%d is newer than this binary (v%d); upgrade aguara",
			snap.SchemaVersion, CurrentSchemaVersion)
	}
	return &snap, nil
}

// Status returns the current Store status. It never fails: missing
// files produce a zero-valued Status with HasSnapshot=false.
//
// A read error on the snapshot file does NOT propagate up; Status
// records the error in LastUpdateErr and returns. Callers that
// need to react to the error (e.g. show a warning) can read that
// field.
func (s *Store) Status() Status {
	st := Status{Path: s.snapshotPath()}
	snap, err := s.Load()
	switch {
	case err == nil:
		st.HasSnapshot = true
		st.GeneratedAt = snap.GeneratedAt
		st.RecordCount = len(snap.Records)
	case errors.Is(err, os.ErrNotExist):
		// No snapshot yet -- not an error condition.
	default:
		st.LastUpdateErr = err.Error()
	}
	return st
}
