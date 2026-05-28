package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SnapshotMeta is a small, human-reviewable sidecar describing an
// embedded snapshot blob. It is committed next to the gzipped blob
// (which git treats as binary) so a reviewer can see what changed in a
// pull request -- record count, ecosystems, content hashes, sizes --
// without decompressing anything.
//
// It is integrity metadata, not a signature: a test asserts these
// hashes match the embedded blob, catching a blob regenerated without
// refreshing its meta (or vice versa) so a future diff is never "just
// a binary changed".
type SnapshotMeta struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	RecordCount   int       `json:"record_count"`
	SourceCount   int       `json:"source_count"`
	Ecosystems    []string  `json:"ecosystems"`
	JSONSHA256    string    `json:"json_sha256"`
	GzipSHA256    string    `json:"gzip_sha256"`
	JSONBytes     int       `json:"json_bytes"`
	GzipBytes     int       `json:"gzip_bytes"`
}

// BuildSnapshotMeta derives the sidecar metadata for snap from its
// canonical JSON bytes and gzipped bytes (as produced by
// MarshalSnapshotJSON / EncodeSnapshotGZIP). The exact bytes are passed
// in -- not recomputed -- so the hashes provably describe the blob that
// actually ships.
func BuildSnapshotMeta(snap Snapshot, jsonBytes, gzBytes []byte) SnapshotMeta {
	jsonSum := sha256.Sum256(jsonBytes)
	gzSum := sha256.Sum256(gzBytes)
	return SnapshotMeta{
		SchemaVersion: snap.SchemaVersion,
		GeneratedAt:   snap.GeneratedAt,
		RecordCount:   len(snap.Records),
		SourceCount:   len(snap.Sources),
		Ecosystems:    EcosystemsFromSources(snap.Sources),
		JSONSHA256:    hex.EncodeToString(jsonSum[:]),
		GzipSHA256:    hex.EncodeToString(gzSum[:]),
		JSONBytes:     len(jsonBytes),
		GzipBytes:     len(gzBytes),
	}
}
