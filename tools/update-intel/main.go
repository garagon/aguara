// Command update-intel regenerates the embedded advisory snapshot
// (internal/incident/generated_intel.json.gz plus its
// generated_intel.meta.json sidecar) from one or more OSV.dev all.zip
// dumps.
//
// Production invocation reads zip dumps from local disk (the maintainer
// downloads them out-of-band via curl/wget) so the importer never
// touches the network from within `aguara`. v0.17 ships all 8
// supported ecosystems in the embedded snapshot, so a release-prep
// regeneration passes one --from-zip / --ecosystem pair per ecosystem:
//
//	go run ./tools/update-intel \
//	    --from-zip ./osv-npm.zip       --ecosystem npm \
//	    --from-zip ./osv-pypi.zip      --ecosystem PyPI \
//	    --from-zip ./osv-go.zip        --ecosystem Go \
//	    --from-zip ./osv-crates.io.zip --ecosystem crates.io \
//	    --from-zip ./osv-packagist.zip --ecosystem Packagist \
//	    --from-zip ./osv-rubygems.zip  --ecosystem RubyGems \
//	    --from-zip ./osv-maven.zip     --ecosystem Maven \
//	    --from-zip ./osv-nuget.zip     --ecosystem NuGet \
//	    --out internal/incident/generated_intel.json.gz
//
// The snapshot is written as deterministic gzipped JSON (see
// intel.EncodeSnapshotGZIP); the sidecar metadata records record
// counts, ecosystems, and content hashes so a regeneration is
// reviewable even though the blob is binary.
//
// A regeneration that forgets one of the 8 pairs is caught by
// TestEmbeddedSnapshotCoversAllEightEcosystems in
// internal/incident: the test asserts every SupportedEcosystems()
// entry has a SourceMeta in the snapshot.
//
// The flag pairs --from-zip / --ecosystem are positional: the Nth
// zip is interpreted under the Nth ecosystem filter. Mismatched
// pair counts fail loudly so the maintainer cannot silently mis-tag
// a dump.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/osvimport"
)

// multiFlag is a flag.Value that accumulates string values across
// repeated flag occurrences. The standard library's flag.StringVar
// only keeps the last value; multiFlag keeps all of them so a
// single command line can declare multiple --from-zip / --ecosystem
// inputs without resorting to comma-splitting.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var (
		zips        multiFlag
		ecosystems  multiFlag
		outPath     string
		genTime     string
		toolVersion string
		allowEmpty  bool
	)

	fs := flag.NewFlagSet("update-intel", flag.ContinueOnError)
	fs.Var(&zips, "from-zip", "Path to an OSV ecosystem all.zip (repeatable; pair with --ecosystem)")
	fs.Var(&ecosystems, "ecosystem", "OSV ecosystem for the matching --from-zip (repeatable; e.g. npm, PyPI)")
	fs.StringVar(&outPath, "out", "internal/incident/generated_intel.json.gz", "Path to the gzipped-JSON snapshot blob to write (a .meta.json sidecar is written alongside)")
	fs.StringVar(&genTime, "generated-at", "", "Override the snapshot timestamp (RFC3339; defaults to now). Use this for reproducible builds.")
	fs.StringVar(&toolVersion, "tool-version", "", "aguara version that produced the bundle, recorded in the manifest (e.g. v0.21.0). The intel-publish workflow sets this; leave empty for the committed embedded manifest.")
	fs.BoolVar(&allowEmpty, "allow-empty", false, "Allow an ecosystem to produce zero records (default: error). Use only for initial bootstrap.")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if len(zips) == 0 {
		fmt.Fprintln(os.Stderr, "update-intel: at least one --from-zip required (HTTP download is not yet supported; download the OSV dump manually first)")
		os.Exit(2)
	}
	if len(zips) != len(ecosystems) {
		fmt.Fprintf(os.Stderr, "update-intel: --from-zip and --ecosystem must come in equal counts; got %d zip(s) and %d ecosystem(s)\n",
			len(zips), len(ecosystems))
		os.Exit(2)
	}

	var generatedAt time.Time
	if genTime != "" {
		parsed, err := time.Parse(time.RFC3339, genTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "update-intel: --generated-at must be RFC3339, got %q: %v\n", genTime, err)
			os.Exit(2)
		}
		generatedAt = parsed.UTC()
	}

	merged := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
	}
	if !generatedAt.IsZero() {
		merged.GeneratedAt = generatedAt
	}

	for i, zipPath := range zips {
		eco := ecosystems[i]
		snap, err := importOne(zipPath, []string{eco}, generatedAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "update-intel: import %s (%s): %v\n", zipPath, eco, err)
			os.Exit(1)
		}
		// Zero records for an ecosystem usually means the zip was
		// paired with the wrong --ecosystem (e.g. the PyPI zip
		// tagged as npm) or the zip is empty/malformed. Either
		// way, silently overwriting generated_intel.go with empty
		// intel for that ecosystem is the wrong release outcome.
		// --allow-empty exists for the one legitimate case --
		// bootstrapping a brand-new generated file where the
		// maintainer wants the empty stub committed.
		if len(snap.Records) == 0 && len(snap.AllVersions) == 0 && !allowEmpty {
			fmt.Fprintf(os.Stderr,
				"update-intel: %s (%s) produced 0 records and 0 all-versions entries. The zip may be paired with the wrong --ecosystem or have no malicious entries.\n"+
					"             Pass --allow-empty to commit an empty snapshot anyway.\n",
				zipPath, eco)
			os.Exit(1)
		}
		if merged.GeneratedAt.IsZero() {
			merged.GeneratedAt = snap.GeneratedAt
		}
		merged.Sources = append(merged.Sources, snap.Sources...)
		merged.Records = append(merged.Records, snap.Records...)
		merged.AllVersions = append(merged.AllVersions, snap.AllVersions...)
	}
	osvimport.SortRecords(merged.Records)
	merged.AllVersions = osvimport.SortAndDedupeAllVersions(merged.AllVersions)

	jsonBytes, err := intel.MarshalSnapshotJSON(merged)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: marshal json: %v\n", err)
		os.Exit(1)
	}
	gz, err := intel.EncodeSnapshotGZIP(merged)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: encode: %v\n", err)
		os.Exit(1)
	}
	meta := intel.BuildSnapshotMeta(merged, jsonBytes, gz, filepath.Base(outPath), toolVersion)
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: marshal meta: %v\n", err)
		os.Exit(1)
	}
	metaJSON = append(metaJSON, '\n')

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: resolve --out: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(absOut), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: mkdir %s: %v\n", filepath.Dir(absOut), err)
		os.Exit(1)
	}
	if err := os.WriteFile(absOut, gz, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: write %s: %v\n", absOut, err)
		os.Exit(1)
	}
	metaOut := metaPathFor(absOut)
	if err := os.WriteFile(metaOut, metaJSON, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "update-intel: write %s: %v\n", metaOut, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "update-intel: wrote %d records (%d gz bytes) to %s and metadata to %s\n",
		len(merged.Records), len(gz), absOut, metaOut)
}

// metaPathFor returns the sidecar metadata path for a blob path: it
// swaps a trailing ".json.gz" for ".meta.json", or appends ".meta.json"
// for any other extension so the two files always travel together.
func metaPathFor(blobPath string) string {
	if strings.HasSuffix(blobPath, ".json.gz") {
		return strings.TrimSuffix(blobPath, ".json.gz") + ".meta.json"
	}
	return blobPath + ".meta.json"
}

// importOne opens a single OSV zip, reads its full size, and feeds
// it to the importer with the supplied ecosystem filter. Kept as a
// helper so main() reads as a top-level orchestration.
func importOne(zipPath string, ecosystems []string, generatedAt time.Time) (intel.Snapshot, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return intel.Snapshot{}, fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return intel.Snapshot{}, fmt.Errorf("stat zip: %w", err)
	}
	return osvimport.ImportFromZip(f, info.Size(), osvimport.Options{
		Ecosystems:  ecosystems,
		GeneratedAt: generatedAt,
		SourceName:  fmt.Sprintf("osv.dev/%s", strings.ToLower(ecosystems[0])),
	})
}
