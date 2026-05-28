package bundle

import (
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
)

// validTriple builds a self-consistent snapshot + manifest + gzipped
// blob, so the content checks can be exercised hermetically without
// minting a Sigstore signature (the signature path is covered by the
// verify_test.go fixtures).
func validTriple(t *testing.T) (intel.SnapshotMeta, []byte) {
	t.Helper()
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, time.May, 28, 0, 0, 0, 0, time.UTC),
		Sources: []intel.SourceMeta{{
			Name: "osv.dev/npm", Kind: intel.SourceOSV, URL: "https://osv.dev",
		}},
		Records: []intel.Record{{
			ID: "MAL-2026-1", Ecosystem: intel.EcosystemNPM, Name: "evil-pkg",
			Kind: intel.KindMalicious, Summary: "Malicious npm package", Versions: []string{"1.0.0"},
		}},
	}
	jsonBytes, err := intel.MarshalSnapshotJSON(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gz, err := intel.EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	meta := intel.BuildSnapshotMeta(snap, jsonBytes, gz, ExpectedBlobName, "vtest")
	return meta, gz
}

func TestCheckManifestAgainstBlobValid(t *testing.T) {
	meta, gz := validTriple(t)
	snap, err := checkManifestAgainstBlob(meta, gz)
	if err != nil {
		t.Fatalf("valid triple must pass, got: %v", err)
	}
	if len(snap.Records) != 1 || snap.Records[0].ID != "MAL-2026-1" {
		t.Fatalf("unexpected decoded snapshot: %+v", snap.Records)
	}
}

func TestCheckManifestAgainstBlobRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*intel.SnapshotMeta)
	}{
		{"wrong blob name", func(m *intel.SnapshotMeta) { m.Blob = "evil.json.gz" }},
		{"gzip_sha256 mismatch", func(m *intel.SnapshotMeta) { m.GzipSHA256 = "00" + m.GzipSHA256[2:] }},
		{"gzip_bytes mismatch", func(m *intel.SnapshotMeta) { m.GzipBytes++ }},
		{"json_sha256 mismatch", func(m *intel.SnapshotMeta) { m.JSONSHA256 = "00" + m.JSONSHA256[2:] }},
		{"json_bytes mismatch", func(m *intel.SnapshotMeta) { m.JSONBytes++ }},
		{"bundle_schema_version mismatch", func(m *intel.SnapshotMeta) { m.BundleSchemaVersion = intel.CurrentSchemaVersion + 5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, gz := validTriple(t)
			tc.mutate(&meta)
			if _, err := checkManifestAgainstBlob(meta, gz); err == nil {
				t.Fatalf("expected rejection for %q", tc.name)
			}
		})
	}
}
