package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/garagon/aguara/internal/intel"
)

// ExpectedBlobName is the filename the manifest's `blob` field must
// name. The fetch side downloads this artifact; the check guards
// against a manifest/blob mismatch (a publishing mistake) even after the
// signature verifies.
const ExpectedBlobName = "generated_intel.json.gz"

// VerifyAndDecode is the full fresh-bundle gate. It verifies the
// manifest's signature under the pinned identity, then validates the
// manifest against the downloaded blob bytes, and returns the decoded
// snapshot. It returns a non-nil error on ANY failure so the caller can
// fail closed and never write a partially-validated bundle to the cache.
//
// Checks, in order:
//  1. manifest signed by the pinned identity (Sigstore bundle)
//  2. manifest_schema present (>= 1) and <= supported
//  3. blob == ExpectedBlobName
//  4. gzip_sha256 == sha256(blob); gzip_bytes == len(blob)
//  5. decompress blob; json_sha256 == sha256(json); json_bytes == len(json)
//  6. decode snapshot; bundle_schema_version == snapshot.SchemaVersion
func VerifyAndDecode(manifestBytes, bundleBytes, blobBytes []byte) (intel.Snapshot, error) {
	meta, err := VerifyAndParse(manifestBytes, bundleBytes)
	if err != nil {
		return intel.Snapshot{}, err
	}
	return checkManifestAgainstBlob(meta, blobBytes)
}

// DecodeUnverified parses and content-validates the manifest against the
// blob WITHOUT verifying the Sigstore signature or publisher identity. It
// still enforces manifest_schema (present + supported), the blob name,
// the gzip/json digests + sizes, and the snapshot decode -- it only skips
// the cryptographic trust check.
//
// This backs --insecure-intel, which is gated behind both a flag and an
// env var at the CLI and is intended only for mirrors, air-gapped
// re-hosting, and tests. It must never be reachable from config.
func DecodeUnverified(manifestBytes, blobBytes []byte) (intel.Snapshot, error) {
	meta, err := parseManifest(manifestBytes)
	if err != nil {
		return intel.Snapshot{}, err
	}
	return checkManifestAgainstBlob(meta, blobBytes)
}

// checkManifestAgainstBlob runs the content checks (steps 3-6 above)
// that bind a verified manifest to the downloaded blob. Split from the
// signature path so the content invariants can be unit-tested
// hermetically without minting a Sigstore signature.
func checkManifestAgainstBlob(meta intel.SnapshotMeta, blobBytes []byte) (intel.Snapshot, error) {
	if meta.Blob != ExpectedBlobName {
		return intel.Snapshot{}, fmt.Errorf("bundle: manifest names blob %q, expected %q", meta.Blob, ExpectedBlobName)
	}

	gzSum := sha256.Sum256(blobBytes)
	if got := hex.EncodeToString(gzSum[:]); got != meta.GzipSHA256 {
		return intel.Snapshot{}, fmt.Errorf("bundle: blob gzip_sha256 mismatch (manifest %s, blob %s)", meta.GzipSHA256, got)
	}
	if len(blobBytes) != meta.GzipBytes {
		return intel.Snapshot{}, fmt.Errorf("bundle: blob size %d != manifest gzip_bytes %d", len(blobBytes), meta.GzipBytes)
	}

	raw, err := intel.DecompressGZIP(blobBytes)
	if err != nil {
		return intel.Snapshot{}, fmt.Errorf("bundle: %w", err)
	}
	jsonSum := sha256.Sum256(raw)
	if got := hex.EncodeToString(jsonSum[:]); got != meta.JSONSHA256 {
		return intel.Snapshot{}, fmt.Errorf("bundle: decompressed json_sha256 mismatch (manifest %s, blob %s)", meta.JSONSHA256, got)
	}
	if len(raw) != meta.JSONBytes {
		return intel.Snapshot{}, fmt.Errorf("bundle: decompressed size %d != manifest json_bytes %d", len(raw), meta.JSONBytes)
	}

	snap, err := intel.DecodeSnapshotJSON(raw)
	if err != nil {
		return intel.Snapshot{}, fmt.Errorf("bundle: %w", err)
	}
	if meta.BundleSchemaVersion != snap.SchemaVersion {
		return intel.Snapshot{}, fmt.Errorf("bundle: manifest bundle_schema_version %d != decoded snapshot schema %d",
			meta.BundleSchemaVersion, snap.SchemaVersion)
	}
	return snap, nil
}
