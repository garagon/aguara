package intel

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"
)

func sampleSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, time.May, 17, 0, 0, 0, 0, time.UTC),
		Sources: []SourceMeta{{
			Name:        "osv.dev/npm",
			Kind:        SourceOSV,
			URL:         "https://osv.dev",
			RetrievedAt: time.Date(2026, time.May, 17, 0, 0, 0, 0, time.UTC),
			License:     "CC-BY-4.0",
		}},
		Records: []Record{
			{
				ID:        "MAL-2026-1",
				Ecosystem: EcosystemNPM,
				Name:      "evil-pkg",
				Kind:      KindMalicious,
				Summary:   "Malicious npm package",
				Versions:  []string{"1.0.0", "1.0.1"},
			},
			{
				ID:         "GHSA-xxxx",
				Ecosystem:  EcosystemPyPI,
				Name:       "compromised-pkg",
				Kind:       KindCompromised,
				Summary:    "Compromised release",
				Versions:   []string{"2.3.4"},
				References: []string{"https://example.test/advisory"},
			},
		},
	}
}

func TestEncodeDecodeSnapshotGZIPRoundTrip(t *testing.T) {
	snap := sampleSnapshot()
	gz, err := EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeSnapshotGZIP(gz)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantJSON, err := MarshalSnapshotJSON(snap)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	gotJSON, err := MarshalSnapshotJSON(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatalf("round-trip changed snapshot:\n want=%s\n  got=%s", wantJSON, gotJSON)
	}
}

func TestEncodeSnapshotGZIPDeterministic(t *testing.T) {
	snap := sampleSnapshot()
	a, err := EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode a: %v", err)
	}
	b, err := EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("identical input produced different bytes (%d vs %d)", len(a), len(b))
	}
}

func TestDecodeSnapshotGZIPRejectsGarbage(t *testing.T) {
	if _, err := DecodeSnapshotGZIP([]byte("not gzip")); err == nil {
		t.Fatal("expected error decoding non-gzip input")
	}
}

func TestDecodeSnapshotGZIPRejectsNewerSchema(t *testing.T) {
	snap := sampleSnapshot()
	snap.SchemaVersion = CurrentSchemaVersion + 1
	gz, err := EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeSnapshotGZIP(gz); err == nil {
		t.Fatal("expected error decoding newer-than-supported schema")
	}
}

func TestDecodeSnapshotGZIPEnforcesSizeCap(t *testing.T) {
	// Highly compressible payload that inflates past MaxSnapshotBytes:
	// the gz stays tiny, the decompressed size must trip the cap.
	var buf bytes.Buffer
	huge := bytes.Repeat([]byte("a"), int(MaxSnapshotBytes)+1024)
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(huge); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if _, err := DecompressGZIP(buf.Bytes()); err == nil {
		t.Fatal("expected size-cap error on oversized decompressed payload")
	}
}

func TestBuildSnapshotMeta(t *testing.T) {
	snap := sampleSnapshot()
	jsonBytes, err := MarshalSnapshotJSON(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gz, err := EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	meta := BuildSnapshotMeta(snap, jsonBytes, gz, "generated_intel.json.gz", "v9.9.9")
	if meta.ManifestSchema != ManifestSchema {
		t.Errorf("manifest_schema = %d, want %d", meta.ManifestSchema, ManifestSchema)
	}
	if meta.BundleSchemaVersion != snap.SchemaVersion {
		t.Errorf("bundle_schema_version = %d, want %d", meta.BundleSchemaVersion, snap.SchemaVersion)
	}
	if meta.Blob != "generated_intel.json.gz" {
		t.Errorf("blob = %q, want generated_intel.json.gz", meta.Blob)
	}
	if meta.ToolVersion != "v9.9.9" {
		t.Errorf("tool_version = %q, want v9.9.9", meta.ToolVersion)
	}
	if meta.RecordCount != len(snap.Records) {
		t.Errorf("record_count = %d, want %d", meta.RecordCount, len(snap.Records))
	}
	if meta.SourceCount != len(snap.Sources) {
		t.Errorf("source_count = %d, want %d", meta.SourceCount, len(snap.Sources))
	}
	if meta.JSONBytes != len(jsonBytes) || meta.GzipBytes != len(gz) {
		t.Errorf("byte counts mismatch: meta json=%d gz=%d, actual json=%d gz=%d",
			meta.JSONBytes, meta.GzipBytes, len(jsonBytes), len(gz))
	}
	if len(meta.JSONSHA256) != 64 || len(meta.GzipSHA256) != 64 {
		t.Errorf("expected hex sha256 hashes, got json=%q gz=%q", meta.JSONSHA256, meta.GzipSHA256)
	}
	if len(meta.Ecosystems) != 1 || meta.Ecosystems[0] != EcosystemNPM {
		t.Errorf("ecosystems = %v, want [npm]", meta.Ecosystems)
	}
}
