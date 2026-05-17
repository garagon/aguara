// Package intel models Aguara's supply-chain threat-intel snapshots.
//
// A Snapshot is a self-contained, offline-usable bundle of malicious
// or compromised package records. Snapshots are loaded from one of
// three sources: an embedded build-time bundle that ships in the
// binary, a local on-disk cache refreshed by `aguara update`, or an
// in-memory adapter that wraps the manual KnownCompromised list in
// internal/incident.
//
// This package owns the type system but does no I/O beyond the
// minimal load/save in store.go. Network refresh, OSV import, and
// CLI surface live in higher layers. The package has no dependency
// on internal/incident so that incident can adopt intel without
// causing an import cycle.
package intel

import "time"

// SourceKind identifies how a snapshot's data was produced. Manual
// entries are hand-curated emergency advisories; OSV entries come
// from the OSV.dev dumps consumed at build time or by `aguara update`.
type SourceKind string

const (
	// SourceManual is the hand-curated emergency advisory list
	// (currently incident.KnownCompromised). Always present in the
	// embedded snapshot.
	SourceManual SourceKind = "manual"
	// SourceOSV is OSV.dev data, filtered to high-confidence
	// malicious/compromised records at import time.
	SourceOSV SourceKind = "osv"
)

// RecordKind classifies a Record. Malicious records describe
// packages that exist specifically to harm consumers; compromised
// records describe legitimate packages whose specific versions
// shipped attacker-controlled code.
//
// The distinction matters for user messaging: a malicious package
// must always be removed; a compromised package may have a clean
// fixed version to pin to.
type RecordKind string

const (
	// KindMalicious -- package was published with malicious intent.
	KindMalicious RecordKind = "malicious"
	// KindCompromised -- legitimate package whose specific versions
	// were compromised (e.g. event-stream 3.3.6).
	KindCompromised RecordKind = "compromised"
)

// Snapshot is a self-contained, offline-usable bundle of intel
// records. SchemaVersion is bumped any time the serialized shape
// changes incompatibly; Load() rejects unknown schema versions
// rather than guessing how to read them.
type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Sources       []SourceMeta `json:"sources"`
	Records       []Record     `json:"records"`
	// SHA256 is optional metadata (set by the build-time generator
	// or `aguara update`). It is NOT used to validate the snapshot
	// during load -- the loader validates by re-parsing the JSON
	// and enforcing size caps. The field is preserved so callers
	// can show provenance to the user.
	SHA256 string `json:"sha256,omitempty"`
}

// CurrentSchemaVersion is the on-disk schema version this build
// understands. Older snapshots may still load if the type evolves
// additively; incompatible changes must bump this constant.
const CurrentSchemaVersion = 1

// SourceMeta describes where a slice of records came from. A single
// Snapshot may aggregate multiple sources (manual + OSV/npm + OSV/PyPI).
type SourceMeta struct {
	Name        string     `json:"name"`
	Kind        SourceKind `json:"kind"`
	URL         string     `json:"url,omitempty"`
	RetrievedAt time.Time  `json:"retrieved_at,omitempty"`
	License     string     `json:"license,omitempty"`
}

// Record is one malicious/compromised package entry.
//
// Versions holds exact affected versions; Ranges holds OSV-style
// ranges. The first implementation only consults Versions -- ranges
// are reserved for a later PR that adds tested semver/PEP440
// support. Importers that produce ranges-only records must also
// emit at least one entry in Versions, or the record is skipped at
// import time (so a partial range parser cannot silently
// under-match).
type Record struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases,omitempty"`
	Ecosystem  string         `json:"ecosystem"`
	Name       string         `json:"name"`
	Kind       RecordKind     `json:"kind"`
	Severity   string         `json:"severity,omitempty"`
	Summary    string         `json:"summary"`
	Versions   []string       `json:"versions,omitempty"`
	Ranges     []VersionRange `json:"ranges,omitempty"`
	References []string       `json:"references,omitempty"`
	IOCs       []IOC          `json:"iocs,omitempty"`
	Withdrawn  bool           `json:"withdrawn,omitempty"`
}

// VersionRange captures an OSV-style affected range. Type names the
// version-grammar (semver, pep440, ecosystem); fields follow the
// OSV semantics: Introduced is inclusive, Fixed is exclusive,
// LastAffected is inclusive of the last bad version.
//
// VersionRange is wire-format only in the first implementation:
// Matcher does not consult ranges. Importers should set Versions
// instead until range support lands with tests.
type VersionRange struct {
	Type         string `json:"type,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// IOC is a single indicator of compromise associated with a record.
// Type names the indicator class ("path", "hash", "endpoint",
// "domain"); Value is the literal string a detector looks for. IOCs
// are optional and additive -- older records without them continue
// to match by (Ecosystem, Name, Version) alone.
type IOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Ecosystem identifiers used across the intel package. Snapshot
// records and MatchInput use the strings on the right; each value
// is the OSV bucket key exactly as OSV.dev publishes it
// (case-sensitive). The ecosystem registry in ecosystem.go maps
// CLI / config aliases ("python", "rust", "golang", ...) onto these
// IDs; the Normalize* helpers in matcher.go consult the registry
// to apply per-ecosystem name canonicalisation.
const (
	EcosystemNPM       = "npm"
	EcosystemPyPI      = "PyPI"
	EcosystemGo        = "Go"
	EcosystemCargo     = "crates.io"
	EcosystemPackagist = "Packagist"
	EcosystemRubyGems  = "RubyGems"
	EcosystemMaven     = "Maven"
	EcosystemNuGet     = "NuGet"
)
