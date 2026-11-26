//go:build unix

package intel_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/garagon/aguara/internal/intel"
)

// A named pipe in the intel cache, as the snapshot or as the provenance
// marker, is an error instead of a read that blocks.
func TestStoreRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	for _, name := range []string{"snapshot.json", "verified.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store := &intel.Store{Dir: dir}
			require.NoError(t, store.Save(intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, GeneratedAt: time.Now().UTC()}))
			target := filepath.Join(dir, name)
			_ = os.Remove(target)
			if err := unix.Mkfifo(target, 0o600); err != nil {
				t.Skipf("mkfifo unavailable: %v", err)
			}
			done := make(chan error, 2)
			go func() {
				_, err := store.Load()
				done <- err
				_, err = store.LoadVerified()
				done <- err
			}()
			for call := range 2 {
				select {
				case err := <-done:
					// Load reads only the snapshot; LoadVerified also the marker.
					if call == 1 || name == "snapshot.json" {
						require.Error(t, err, "a named pipe in the cache is not readable intel")
					} else {
						require.NoError(t, err)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("intel store read blocked on a named pipe %s", target)
				}
			}
		})
	}
}
