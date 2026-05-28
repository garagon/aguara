package intel

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// MarshalSnapshotJSON returns the canonical, compact JSON encoding of
// snap. This is the exact byte sequence that EncodeSnapshotGZIP gzips
// into the embedded blob and that BuildSnapshotMeta hashes, so every
// producer and consumer (build-time generator, runtime decode,
// integrity tests) agrees on one representation.
//
// Field order is deterministic (Go marshals struct fields in
// declaration order and Snapshot holds no maps); record order is the
// caller's responsibility (the generator sorts via
// osvimport.SortRecords before encoding).
func MarshalSnapshotJSON(snap Snapshot) ([]byte, error) {
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("intel: marshal snapshot json: %w", err)
	}
	return data, nil
}

// EncodeSnapshotGZIP marshals snap to canonical JSON and gzips it
// deterministically: identical input under the same Go toolchain
// produces byte-identical output. The gzip header carries no modtime,
// name, comment, or host-OS byte, so the bytes never vary with where
// or when the file was built. (DEFLATE output can differ across Go
// releases; the committed blob is the source of truth and regeneration
// is a deliberate, reviewed step on a known toolchain.)
func EncodeSnapshotGZIP(snap Snapshot) ([]byte, error) {
	data, err := MarshalSnapshotJSON(snap)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("intel: gzip writer: %w", err)
	}
	// Pin every header field that would otherwise leak build context
	// into the bytes (gzip.Writer embeds gzip.Header, so these are
	// promoted). ModTime zero writes 0 (no timestamp); OS 255 is
	// "unknown".
	zw.ModTime = time.Time{}
	zw.OS = 255
	zw.Name = ""
	zw.Comment = ""
	zw.Extra = nil
	if _, err := zw.Write(data); err != nil {
		return nil, fmt.Errorf("intel: gzip write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("intel: gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

// DecodeSnapshotGZIP gunzips and JSON-decodes a snapshot blob produced
// by EncodeSnapshotGZIP. It enforces the same MaxSnapshotBytes cap and
// schema-version checks as Store.Load, so a corrupted blob or one
// written by a newer binary fails loudly rather than mis-loading.
func DecodeSnapshotGZIP(data []byte) (Snapshot, error) {
	raw, err := DecompressGZIP(data)
	if err != nil {
		return Snapshot{}, err
	}
	return DecodeSnapshotJSON(raw)
}

// DecodeSnapshotJSON decodes the decompressed canonical JSON of a
// snapshot and enforces the schema-version check. Exposed so a verified
// fresh bundle can be decoded from already-decompressed bytes (whose
// digest the manifest pins) without gunzipping twice.
func DecodeSnapshotJSON(raw []byte) (Snapshot, error) {
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("intel: decode snapshot json: %w", err)
	}
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = CurrentSchemaVersion
	}
	if snap.SchemaVersion > CurrentSchemaVersion {
		return Snapshot{}, fmt.Errorf("intel: snapshot schema v%d is newer than this binary (v%d); upgrade aguara",
			snap.SchemaVersion, CurrentSchemaVersion)
	}
	return snap, nil
}

// DecompressGZIP inflates data with the MaxSnapshotBytes cap applied to
// the decompressed size, so a malformed or hostile blob cannot cause
// unbounded allocation. +1 byte distinguishes "exactly the cap" from
// "exceeded the cap". Exposed so a fresh-bundle verifier can hash the
// decompressed bytes against the manifest's json_sha256.
func DecompressGZIP(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("intel: gzip reader: %w", err)
	}
	defer func() { _ = zr.Close() }()
	raw, err := io.ReadAll(io.LimitReader(zr, MaxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("intel: gzip read: %w", err)
	}
	if int64(len(raw)) > MaxSnapshotBytes {
		return nil, fmt.Errorf("intel: decompressed snapshot exceeds %d bytes (cap)", MaxSnapshotBytes)
	}
	return raw, nil
}
