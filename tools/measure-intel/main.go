// Command measure-intel reports the size, record yield, and embed
// cost of each OSV ecosystem dump.
//
// Background. PR #0 of the v0.17.0 multi-ecosystem expansion. Before
// committing to embedding Go / crates.io / Packagist / RubyGems /
// Maven / NuGet OSV snapshots in the Aguara binary by default, the
// maintainer needs concrete numbers per ecosystem:
//
//   - compressed all.zip size (network + GHA artifact cost)
//   - total records OSV publishes for the ecosystem
//   - records this importer would actually KEEP (after the
//     "exact-versions present AND signal-or-keyword pass" filter)
//   - records dropped because they only carry ranges (the runtime
//     matcher cannot consume ranges today)
//   - generated Go source size (proxy for binary growth; embedding
//     a 30 MB Go source roughly 3x the source as committed file +
//     ~1-2x in the stripped binary).
//
// The numbers feed the embed-vs-opt-in decision for PR #4. If an
// ecosystem ships 50k OSV records but 95% are ranges-only that the
// matcher cannot use, we do NOT advertise it as covered yet; if
// Maven / NuGet snapshots are too large, they ship as `aguara update
// --ecosystem maven` opt-in rather than embedded default.
//
// The tool is dev-only. It is NOT shipped in any distribution
// channel and is not invoked from `make test` / `make lint`. The
// maintainer runs it manually:
//
//	# Download all 6 buckets then measure
//	go run ./tools/measure-intel --download
//
//	# Measure from already-downloaded local zips
//	go run ./tools/measure-intel \
//	    --from-zip ./osv-cache/Go.zip --ecosystem Go \
//	    --from-zip ./osv-cache/crates.io.zip --ecosystem crates.io
//
//	# Emit JSON instead of the Markdown table (for the PR body
//	# generator or a follow-up architecture decision doc).
//	go run ./tools/measure-intel --download --format json
//
// Filter logic. The per-record gate mirrors osvimport.convertOSVRecord
// (exact-versions present + signal-or-keyword pass). The mirror is
// intentional: this tool must NOT depend on osvimport's hardcoded
// canonicaliseEcosystem (which today rejects everything except npm /
// pypi) but it MUST produce the same counts the importer would
// produce once PR #1 widens canonicaliseEcosystem. The two filter
// implementations are kept in sync by review; any change to the
// importer's filter rules must reproduce here.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/osvimport"
)

// defaultEcosystems is the set PR #0 measures: the 6 ecosystems
// proposed for v0.17.0 multi-ecosystem expansion. npm / PyPI are
// excluded because they already ship embedded; measuring them would
// add noise without changing any decision.
var defaultEcosystems = []string{
	"Go",
	"crates.io",
	"Packagist",
	"RubyGems",
	"Maven",
	"NuGet",
}

// osvURLTemplate is the OSV.dev public bucket layout. The {{eco}}
// placeholder is substituted at fetch time with the ecosystem name
// exactly as OSV publishes it (case-sensitive). The path follows the
// pattern OSV documents at https://google.github.io/osv.dev/data/.
const osvURLTemplate = "https://osv-vulnerabilities.storage.googleapis.com/{{eco}}/all.zip"

// downloadTimeout caps a single zip fetch. Maven and NuGet dumps
// can be hundreds of MB; the cap protects against a stalled CDN
// without aborting a healthy multi-minute download.
const downloadTimeout = 10 * time.Minute

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	var (
		ecosystems multiFlag
		zips       multiFlag
		zipEcos    multiFlag
		download   bool
		cacheDir   string
		format     string
		urlTmpl    string
	)

	fs := flag.NewFlagSet("measure-intel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&ecosystems, "ecosystem", "Ecosystem to measure (repeatable; OSV string e.g. Go, crates.io, Maven). Default: all 6 v0.17.0 candidates.")
	fs.Var(&zips, "from-zip", "Path to a local OSV all.zip (repeatable; pair positionally with --from-zip-ecosystem).")
	fs.Var(&zipEcos, "from-zip-ecosystem", "Ecosystem string for the matching --from-zip (repeatable).")
	fs.BoolVar(&download, "download", false, "Fetch OSV all.zip for each ecosystem into --cache-dir. Required to make network calls.")
	fs.StringVar(&cacheDir, "cache-dir", ".intel-cache", "Directory to read/write cached OSV zips.")
	fs.StringVar(&format, "format", "markdown", "Output format: markdown or json.")
	fs.StringVar(&urlTmpl, "url-template", osvURLTemplate, "OSV bucket URL template; {{eco}} is replaced with the ecosystem string.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if format != "markdown" && format != "json" {
		return fmt.Errorf("--format must be markdown or json, got %q", format)
	}

	jobs, err := resolveJobs(ecosystems, zips, zipEcos, download, cacheDir, urlTmpl, stderr)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return errors.New("no ecosystems to measure; pass --ecosystem or --from-zip / --from-zip-ecosystem")
	}

	reports := make([]ecosystemReport, 0, len(jobs))
	for _, job := range jobs {
		fmt.Fprintf(stderr, ">> measuring %s (%s)...\n", job.ecosystem, job.zipPath)
		r, err := measure(job)
		if err != nil {
			return fmt.Errorf("measure %s: %w", job.ecosystem, err)
		}
		reports = append(reports, r)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Ecosystem < reports[j].Ecosystem })

	switch format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			GeneratedAt time.Time         `json:"generated_at"`
			Reports     []ecosystemReport `json:"reports"`
		}{
			GeneratedAt: time.Now().UTC(),
			Reports:     reports,
		})
	default:
		return renderMarkdown(stdout, reports)
	}
}

// measureJob pairs an ecosystem string with the local zip path the
// tool will read. resolveJobs is the single source of truth for
// where the zip comes from (explicit --from-zip, cache hit, or
// network download); measure() does not touch the network or cache
// logic.
type measureJob struct {
	ecosystem string
	zipPath   string
}

func resolveJobs(ecosystems, zips, zipEcos multiFlag, download bool, cacheDir, urlTmpl string, stderr io.Writer) ([]measureJob, error) {
	// Explicit --from-zip wins. The pair --from-zip/--from-zip-ecosystem
	// is positional; mismatched pair counts is a typo we must surface
	// (silent fallthrough would mis-tag a dump).
	if len(zips) != len(zipEcos) {
		return nil, fmt.Errorf("--from-zip count (%d) must match --from-zip-ecosystem count (%d)", len(zips), len(zipEcos))
	}
	var jobs []measureJob
	for i, z := range zips {
		jobs = append(jobs, measureJob{ecosystem: zipEcos[i], zipPath: z})
	}

	// --ecosystem fills in any ecosystems the user did not provide
	// via --from-zip. The default set kicks in only when both
	// --ecosystem and --from-zip are empty.
	ecoTargets := []string(ecosystems)
	if len(ecoTargets) == 0 && len(zips) == 0 {
		ecoTargets = append(ecoTargets, defaultEcosystems...)
	}

	for _, eco := range ecoTargets {
		// Skip ecosystems already covered by --from-zip so we do
		// not double-measure the same input.
		if containsEco(zipEcos, eco) {
			continue
		}
		zipPath := filepath.Join(cacheDir, eco+".zip")
		if _, err := os.Stat(zipPath); err == nil {
			jobs = append(jobs, measureJob{ecosystem: eco, zipPath: zipPath})
			continue
		}
		if !download {
			return nil, fmt.Errorf(
				"no local zip for %s at %s and --download not set; pass --download to fetch, or supply --from-zip",
				eco, zipPath,
			)
		}
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("create cache dir: %w", err)
		}
		url := strings.ReplaceAll(urlTmpl, "{{eco}}", eco)
		fmt.Fprintf(stderr, "  downloading %s -> %s\n", url, zipPath)
		if err := fetchZip(url, zipPath); err != nil {
			return nil, fmt.Errorf("download %s: %w", eco, err)
		}
		jobs = append(jobs, measureJob{ecosystem: eco, zipPath: zipPath})
	}
	return jobs, nil
}

func containsEco(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

func fetchZip(url, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	// Write through a temp file so a torn download does not leave a
	// corrupt zip in the cache that subsequent invocations would
	// pick up. Rename is atomic on the same filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(dest), "intel-zip-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

// ecosystemReport is the per-ecosystem counter set the tool emits.
// JSON tags are lower_snake so the report is consumable by a
// downstream architecture-decision script without name munging.
type ecosystemReport struct {
	Ecosystem string `json:"ecosystem"`
	ZipPath   string `json:"zip_path"`
	// Sizes
	ZipCompressedBytes   int64 `json:"zip_compressed_bytes"`
	ZipDecompressedBytes int64 `json:"zip_decompressed_bytes"`
	GeneratedSourceBytes int64 `json:"generated_source_bytes"`
	// Record counts: read top-to-bottom for the funnel.
	TotalRecords             int `json:"total_records"`
	EcosystemMatchedRecords  int `json:"ecosystem_matched_records"`
	WithdrawnRecords         int `json:"withdrawn_records"`
	RangesOnlyDroppedRecords int `json:"ranges_only_dropped_records"`
	SignalOrKeywordKept      int `json:"signal_or_keyword_kept_records"`
	NeitherDroppedRecords    int `json:"neither_dropped_records"`
	FinalKeptRecords         int `json:"final_kept_records"`
	// Timing
	ParseDurationMS    int64 `json:"parse_duration_ms"`
	RenderDurationMS   int64 `json:"render_duration_ms"`
}

func measure(job measureJob) (ecosystemReport, error) {
	r := ecosystemReport{Ecosystem: job.ecosystem, ZipPath: job.zipPath}

	info, err := os.Stat(job.zipPath)
	if err != nil {
		return r, fmt.Errorf("stat zip: %w", err)
	}
	r.ZipCompressedBytes = info.Size()

	f, err := os.Open(job.zipPath)
	if err != nil {
		return r, fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = f.Close() }()

	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return r, fmt.Errorf("open zip reader: %w", err)
	}

	parseStart := time.Now()
	var kept []intel.Record
	for _, entry := range zr.File {
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		data, err := readZipEntry(entry)
		if err != nil {
			// Skip malformed entries rather than abort; OSV
			// dumps occasionally include bookkeeping files that
			// fail to parse but should not invalidate the run.
			continue
		}
		r.ZipDecompressedBytes += int64(len(data))
		r.TotalRecords++

		rec, status := classifyRecord(data, job.ecosystem)
		switch status {
		case statusEcosystemMiss:
			// nothing to count beyond TotalRecords
		case statusWithdrawn:
			r.EcosystemMatchedRecords++
			r.WithdrawnRecords++
		case statusRangesOnly:
			r.EcosystemMatchedRecords++
			r.RangesOnlyDroppedRecords++
		case statusNeither:
			r.EcosystemMatchedRecords++
			r.NeitherDroppedRecords++
		case statusKeptSignal, statusKeptKeyword:
			r.EcosystemMatchedRecords++
			r.SignalOrKeywordKept++
			r.FinalKeptRecords++
			kept = append(kept, rec)
		}
	}
	r.ParseDurationMS = time.Since(parseStart).Milliseconds()

	// Sort kept records into the canonical (ecosystem, name, ID)
	// order osvimport.RenderGoSource expects so the size estimate
	// matches a real generated file byte-for-byte.
	osvimport.SortRecords(kept)

	renderStart := time.Now()
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, time.May, 16, 0, 0, 0, 0, time.UTC),
		Sources: []intel.SourceMeta{{
			Name:        "osv.dev/" + strings.ToLower(job.ecosystem),
			Kind:        intel.SourceOSV,
			URL:         "https://osv.dev",
			RetrievedAt: time.Date(2026, time.May, 16, 0, 0, 0, 0, time.UTC),
			License:     "CC-BY-4.0",
		}},
		Records: kept,
	}
	src, err := osvimport.RenderGoSource(snap, osvimport.RenderConfig{
		Package: "incident",
		VarName: "EmbeddedIntelSnapshot_" + sanitizeForGoIdent(job.ecosystem),
	})
	if err != nil {
		return r, fmt.Errorf("render snapshot: %w", err)
	}
	r.GeneratedSourceBytes = int64(len(src))
	r.RenderDurationMS = time.Since(renderStart).Milliseconds()

	return r, nil
}

// readZipEntry caps a single decompressed entry at 4 MiB (OSV
// records are typically a few KiB). Beyond the cap the entry is
// almost certainly malformed; skipping it keeps the rest of the
// run useful instead of aborting on one bad row.
func readZipEntry(entry *zip.File) ([]byte, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	const cap = 4 * 1024 * 1024
	return io.ReadAll(io.LimitReader(rc, cap))
}

// sanitizeForGoIdent turns an OSV ecosystem string into something
// usable as a Go identifier suffix. OSV publishes "crates.io" with
// a dot, "RubyGems" with mixed case; the renderer needs a plain
// identifier so the variable name compiles.
func sanitizeForGoIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func renderMarkdown(w io.Writer, reports []ecosystemReport) error {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "| Ecosystem | Zip (MB) | Total | Matched | Withdrawn | Ranges-only | Neither | Kept (final) | Gen. source (MB) | Parse (s) |")
	fmt.Fprintln(&buf, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
	for _, r := range reports {
		fmt.Fprintf(&buf, "| %s | %.1f | %d | %d | %d | %d | %d | **%d** | %.2f | %.1f |\n",
			r.Ecosystem,
			float64(r.ZipCompressedBytes)/1024/1024,
			r.TotalRecords,
			r.EcosystemMatchedRecords,
			r.WithdrawnRecords,
			r.RangesOnlyDroppedRecords,
			r.NeitherDroppedRecords,
			r.FinalKeptRecords,
			float64(r.GeneratedSourceBytes)/1024/1024,
			float64(r.ParseDurationMS)/1000,
		)
	}
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "Columns:")
	fmt.Fprintln(&buf, "- **Total**: every JSON record in the zip.")
	fmt.Fprintln(&buf, "- **Matched**: records whose `affected[].package.ecosystem` matches the target.")
	fmt.Fprintln(&buf, "- **Withdrawn**: OSV-retracted; counted in Matched, passed through as tombstones (not in Kept).")
	fmt.Fprintln(&buf, "- **Ranges-only**: matched records dropped because the runtime matcher cannot consume version ranges yet.")
	fmt.Fprintln(&buf, "- **Neither**: matched, has exact versions, but fails BOTH the signal (MAL- prefix / OpenSSF origins) and the keyword gate. These are CVE-flavoured records that do not belong in a malicious-package snapshot.")
	fmt.Fprintln(&buf, "- **Kept (final)**: what would actually become `intel.Record` entries in the embedded snapshot.")
	fmt.Fprintln(&buf, "- **Gen. source**: gofmt'd generated Go source size; a rough upper bound on commit-time bloat. Binary impact is typically smaller after the linker drops unused intermediates.")
	_, err := w.Write(buf.Bytes())
	return err
}
