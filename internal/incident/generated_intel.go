package incident

import (
	_ "embed"
	"sync"

	"github.com/garagon/aguara/internal/intel"
)

// generatedIntelGZ is the OSV-derived snapshot baked into the binary as
// gzipped canonical JSON. It is produced by tools/update-intel from
// OSV.dev all.zip dumps; generated_intel.meta.json (committed alongside)
// carries a human-reviewable summary -- record count, ecosystems, and
// content hashes -- so a regeneration is reviewable even though the blob
// itself is binary.
//
// The snapshot is combined with KnownCompromisedSnapshot() through the
// matcher's merge semantics so manual emergency entries keep display
// priority over OSV refreshes for the same advisory ID.
//
//go:embed generated_intel.json.gz
var generatedIntelGZ []byte

var (
	embeddedIntelOnce sync.Once
	embeddedIntel     intel.Snapshot
)

// EmbeddedIntelSnapshot decodes and returns the build-time OSV snapshot.
// The decode (gunzip + JSON unmarshal) runs once on first use, so
// commands that never consult advisory intel -- scan, version -- do not
// pay for it. A blob that fails to decode is a build-time defect rather
// than a user condition, so it panics; CI exercises this path on every
// run via the incident package tests.
func EmbeddedIntelSnapshot() intel.Snapshot {
	embeddedIntelOnce.Do(func() {
		snap, err := intel.DecodeSnapshotGZIP(generatedIntelGZ)
		if err != nil {
			panic("incident: decode embedded intel snapshot: " + err.Error())
		}
		embeddedIntel = intel.ApplyOSVAdmissionPolicy(snap)
	})
	return embeddedIntel
}
