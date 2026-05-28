package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ManifestSchema is the schema version of the SnapshotMeta document
// itself (distinct from BundleSchemaVersion, which is the intel.Snapshot
// schema the blob decodes to). Bumped only when the manifest shape
// changes incompatibly. Verifiers reject manifests with a higher value.
const ManifestSchema = 1

// SnapshotMeta is the human-reviewable, signable manifest that travels
// with an embedded or published intel blob. It is committed next to the
// gzipped blob (which git treats as binary) so a reviewer can see what
// changed in a pull request, and it is the document the intel-publish
// workflow signs with Cosign keyless so `aguara update` can verify a
// fresh bundle before trusting it.
//
// The hashes provably describe the blob: `gzip_sha256` binds the gzipped
// blob bytes; `json_sha256` binds the decompressed JSON (defense in
// depth). `blob` names the artifact the manifest describes so a verifier
// does not have to assume a filename. Field order matches the published
// contract.
type SnapshotMeta struct {
	// ManifestSchema is this manifest document's own schema version.
	ManifestSchema int `json:"manifest_schema"`
	// BundleSchemaVersion is the intel.Snapshot schema the blob decodes
	// to (intel.CurrentSchemaVersion at generation time).
	BundleSchemaVersion int `json:"bundle_schema_version"`
	// Blob is the filename of the gzipped-JSON blob this manifest
	// describes (e.g. "generated_intel.json.gz").
	Blob string `json:"blob"`
	// GzipSHA256 is the sha256 of the gzipped blob bytes (binds the blob).
	GzipSHA256 string `json:"gzip_sha256"`
	// JSONSHA256 is the sha256 of the decompressed JSON (defense in depth).
	JSONSHA256 string `json:"json_sha256"`
	GzipBytes  int    `json:"gzip_bytes"`
	JSONBytes  int    `json:"json_bytes"`
	RecordCount int    `json:"record_count"`
	SourceCount int    `json:"source_count"`
	Ecosystems  []string  `json:"ecosystems"`
	GeneratedAt time.Time `json:"generated_at"`
	// ToolVersion is the aguara version that produced the bundle. Set by
	// the publishing workflow; omitted from the committed embedded
	// manifest to avoid a version string that drifts every release.
	ToolVersion string `json:"tool_version,omitempty"`
}

// BuildSnapshotMeta derives the manifest for snap from its canonical JSON
// bytes and gzipped bytes (as produced by MarshalSnapshotJSON /
// EncodeSnapshotGZIP). The exact bytes are passed in, not recomputed, so
// the hashes provably describe the artifact that ships. blobName is the
// filename the blob is written as; toolVersion is the producing aguara
// version (pass "" to omit it, e.g. for the committed embedded manifest).
func BuildSnapshotMeta(snap Snapshot, jsonBytes, gzBytes []byte, blobName, toolVersion string) SnapshotMeta {
	jsonSum := sha256.Sum256(jsonBytes)
	gzSum := sha256.Sum256(gzBytes)
	return SnapshotMeta{
		ManifestSchema:      ManifestSchema,
		BundleSchemaVersion: snap.SchemaVersion,
		Blob:                blobName,
		GzipSHA256:          hex.EncodeToString(gzSum[:]),
		JSONSHA256:          hex.EncodeToString(jsonSum[:]),
		GzipBytes:           len(gzBytes),
		JSONBytes:           len(jsonBytes),
		RecordCount:         len(snap.Records),
		SourceCount:         len(snap.Sources),
		Ecosystems:          EcosystemsFromSources(snap.Sources),
		GeneratedAt:         snap.GeneratedAt,
		ToolVersion:         toolVersion,
	}
}
