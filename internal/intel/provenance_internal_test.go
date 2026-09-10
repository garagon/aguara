package intel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStagingFailureDoesNotInvalidateProvenance(t *testing.T) {
	// A missing staging directory exercises the same CreateTemp failure branch
	// as descriptor/disk exhaustion, without exhausting host resources.
	store := &Store{Dir: t.TempDir()}
	if err := store.SaveVerified(Snapshot{SchemaVersion: CurrentSchemaVersion}); err != nil {
		t.Fatal(err)
	}
	staging := &Store{Dir: filepath.Join(t.TempDir(), "missing")}
	called := false
	err := staging.atomicWriteBeforeRename(store.snapshotPath(), []byte("replacement"), func() error {
		called = true
		return os.Remove(store.verifiedMarkerPath())
	})
	if err == nil || called {
		t.Fatalf("staging failure invalidated provenance: called=%v err=%v", called, err)
	}
	if _, err := store.LoadVerified(); err != nil {
		t.Fatalf("previous cache unusable: %v", err)
	}
}

func TestBeforeRenameFailurePreservesSnapshotAndCleansTemp(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	if err := store.SaveVerified(Snapshot{SchemaVersion: CurrentSchemaVersion}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("cannot invalidate")
	err := store.atomicWriteBeforeRename(store.snapshotPath(), []byte("replacement"), func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("unexpected failure: %v", err)
	}
	if _, err := store.LoadVerified(); err != nil {
		t.Fatalf("previous cache unusable: %v", err)
	}
	entries, err := os.ReadDir(store.Dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("temporary file left behind: %v %v", entries, err)
	}
}
