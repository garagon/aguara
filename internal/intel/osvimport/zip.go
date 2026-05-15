package osvimport

import (
	"archive/zip"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// MaxZipBytes caps the size of any OSV zip Import accepts. OSV
// dumps are large (npm all.zip is ~hundreds of MiB), but the
// importer ingests them entirely in memory and we want a hard
// ceiling before the process gets killed by the OOM watchdog.
const MaxZipBytes int64 = 256 * 1024 * 1024

// MaxZipEntryBytes caps a single decompressed entry. OSV records
// are small (a few KiB each); anything beyond this is either a
// degenerate record or a zip bomb.
const MaxZipEntryBytes int64 = 4 * 1024 * 1024

// ImportFromZip reads an OSV all.zip dump and feeds each contained
// JSON file to Import. The reader must support seeking because the
// archive/zip package needs ReaderAt; if you only have an io.Reader
// (e.g. straight from HTTP), buffer it through bytes.NewReader
// first.
//
// Size MUST be the true length of the underlying source; archive/zip
// uses it to locate the central directory. Pass <= 0 to let
// ImportFromZip read it from r.Size if r implements that method
// (avoids one bug class where callers thread the wrong length).
//
// Returns the produced snapshot. Errors come from the zip layer
// (malformed archive, oversize entry) or from the size cap; an
// individual malformed JSON record is silently skipped (per
// Import's contract).
func ImportFromZip(r io.ReaderAt, size int64, opts Options) (intel.Snapshot, error) {
	if size <= 0 {
		return intel.Snapshot{}, fmt.Errorf("osvimport: zip size must be > 0")
	}
	if size > MaxZipBytes {
		return intel.Snapshot{}, fmt.Errorf("osvimport: zip size %d bytes exceeds cap %d", size, MaxZipBytes)
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return intel.Snapshot{}, fmt.Errorf("osvimport: open zip: %w", err)
	}

	var raw [][]byte
	for _, entry := range zr.File {
		if !looksLikeOSVRecord(entry.Name) {
			continue
		}
		if int64(entry.UncompressedSize64) > MaxZipEntryBytes {
			return intel.Snapshot{}, fmt.Errorf("osvimport: entry %q is %d bytes, exceeds entry cap %d",
				entry.Name, entry.UncompressedSize64, MaxZipEntryBytes)
		}
		data, err := readEntry(entry)
		if err != nil {
			return intel.Snapshot{}, fmt.Errorf("osvimport: read entry %q: %w", entry.Name, err)
		}
		raw = append(raw, data)
	}

	return Import(raw, opts)
}

// looksLikeOSVRecord filters zip entries to the JSON records OSV
// dumps actually contain. OSV all.zip puts every record at the
// top level as `<ID>.json`; we exclude metadata files (LICENSE,
// README, *.txt) so they do not waste a parse pass.
//
// Path traversal: archive/zip already rejects entries whose name
// contains `..` traversal, but a defensive Clean here doubles as
// documentation -- we never extract these entries to disk.
func looksLikeOSVRecord(name string) bool {
	cleaned := path.Clean(name)
	if cleaned == "." || strings.HasPrefix(cleaned, "..") || strings.HasPrefix(cleaned, "/") {
		return false
	}
	if strings.Contains(cleaned, "..") {
		return false
	}
	return strings.HasSuffix(cleaned, ".json")
}

// readEntry opens a single zip entry, reads up to MaxZipEntryBytes
// of decompressed data, and returns it. The +1 LimitReader trick
// lets us distinguish "exactly the cap" from "exceeded".
func readEntry(entry *zip.File) ([]byte, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	limited := io.LimitReader(rc, MaxZipEntryBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxZipEntryBytes {
		return nil, fmt.Errorf("entry decompressed past cap %d", MaxZipEntryBytes)
	}
	return data, nil
}
