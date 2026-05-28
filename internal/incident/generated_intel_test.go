package incident

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

// TestEmbeddedIntelMetaMatchesBlob proves the committed sidecar
// metadata (generated_intel.meta.json) describes the embedded blob
// exactly. This is the integrity gate that keeps a future regeneration
// from being "just a binary changed": the meta is human-reviewable, and
// this test fails if the blob and meta ever drift apart.
func TestEmbeddedIntelMetaMatchesBlob(t *testing.T) {
	raw, err := os.ReadFile("generated_intel.meta.json")
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta intel.SnapshotMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}

	// gzip_sha256 / gzip_bytes describe the embedded blob bytes.
	gzSum := sha256.Sum256(generatedIntelGZ)
	if got := hex.EncodeToString(gzSum[:]); got != meta.GzipSHA256 {
		t.Errorf("gzip_sha256 mismatch:\n meta=%s\n blob=%s", meta.GzipSHA256, got)
	}
	if meta.GzipBytes != len(generatedIntelGZ) {
		t.Errorf("gzip_bytes mismatch: meta=%d blob=%d", meta.GzipBytes, len(generatedIntelGZ))
	}

	// json_sha256 / json_bytes describe the decompressed JSON.
	zr, err := gzip.NewReader(bytes.NewReader(generatedIntelGZ))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	jsonBytes, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	_ = zr.Close()
	jsonSum := sha256.Sum256(jsonBytes)
	if got := hex.EncodeToString(jsonSum[:]); got != meta.JSONSHA256 {
		t.Errorf("json_sha256 mismatch:\n meta=%s\n blob=%s", meta.JSONSHA256, got)
	}
	if meta.JSONBytes != len(jsonBytes) {
		t.Errorf("json_bytes mismatch: meta=%d blob=%d", meta.JSONBytes, len(jsonBytes))
	}

	// record_count / source_count / schema / generated_at must match
	// the decoded snapshot the runtime actually serves.
	snap := EmbeddedIntelSnapshot()
	if meta.RecordCount != len(snap.Records) {
		t.Errorf("record_count mismatch: meta=%d snapshot=%d", meta.RecordCount, len(snap.Records))
	}
	if meta.SourceCount != len(snap.Sources) {
		t.Errorf("source_count mismatch: meta=%d snapshot=%d", meta.SourceCount, len(snap.Sources))
	}
	if meta.BundleSchemaVersion != snap.SchemaVersion {
		t.Errorf("bundle_schema_version mismatch: meta=%d snapshot=%d", meta.BundleSchemaVersion, snap.SchemaVersion)
	}
	if !meta.GeneratedAt.Equal(snap.GeneratedAt) {
		t.Errorf("generated_at mismatch: meta=%s snapshot=%s", meta.GeneratedAt, snap.GeneratedAt)
	}
	// Signed-manifest contract fields (PR 0): the committed embedded
	// manifest must carry the manifest schema and name its blob.
	if meta.ManifestSchema != intel.ManifestSchema {
		t.Errorf("manifest_schema = %d, want %d", meta.ManifestSchema, intel.ManifestSchema)
	}
	if meta.Blob != "generated_intel.json.gz" {
		t.Errorf("blob = %q, want generated_intel.json.gz", meta.Blob)
	}
}
