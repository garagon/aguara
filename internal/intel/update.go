package intel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultOSVURLTemplate is the OSV.dev all.zip URL pattern. The
// `%s` slot is filled with the canonical ecosystem identifier
// (npm, PyPI). OSV serves these as static, cacheable blobs so the
// download path is deterministic.
const DefaultOSVURLTemplate = "https://storage.googleapis.com/osv-vulnerabilities/%s/all.zip"

// DefaultHTTPTimeout caps each per-ecosystem download. OSV all.zip
// dumps are large but the CDN is fast; a half-hour ceiling is
// generous-with-headroom and prevents a hung connection from
// stalling `aguara update` indefinitely.
const DefaultHTTPTimeout = 30 * time.Minute

// MaxHTTPBodyBytes caps how many compressed bytes we read from any
// single OSV download. Tied to MaxZipBytes in osvimport so an
// oversize download fails before it can fill memory.
//
// This is intentionally the SAME number as the importer's
// MaxZipBytes (256 MiB) -- once the bytes leave this package they
// hit osvimport's caps anyway, so duplicating the constant here is
// for explicitness, not for layering.
const MaxHTTPBodyBytes int64 = 256 * 1024 * 1024

// UpdateOptions controls a refresh run. All fields are optional;
// zero values are wired in Update so a caller that just wants
// "refresh everything" can pass UpdateOptions{}.
type UpdateOptions struct {
	// Ecosystems to refresh. Empty defaults to [npm, PyPI] -- the
	// two production ecosystems the importer supports. Adding
	// more later requires both an importer canonicalisation
	// entry and a server-side OSV slice.
	Ecosystems []string
	// HTTPClient overrides the client used to fetch OSV dumps.
	// Tests pass httptest.NewServer()'s client; production
	// leaves it nil to use http.DefaultClient with a per-call
	// timeout.
	HTTPClient *http.Client
	// URLTemplate overrides DefaultOSVURLTemplate. Tests use
	// httptest.NewServer().URL + "/%s/all.zip"; production
	// leaves it empty.
	URLTemplate string
	// Now returns the current time. Tests inject a fixed time;
	// production leaves it nil to use time.Now().
	Now func() time.Time
	// Importer overrides the snapshot-builder hook used to
	// parse each downloaded zip. Tests can swap in a stub; the
	// zero value uses osvimport.ImportFromZip.
	Importer ImportFunc
	// Stderr receives one-line progress messages (one per
	// ecosystem) when non-nil. Production wires os.Stderr from
	// the CLI; tests pass nil to suppress output.
	Stderr io.Writer
}

// ImportFunc is the contract intel/update expects from the
// osvimport package without importing it (avoiding the intel ->
// osvimport -> intel cycle). It is satisfied by
// osvimport.ImportFromZip; the CLI wires that in.
type ImportFunc func(r io.ReaderAt, size int64, ecosystems []string, generatedAt time.Time) (Snapshot, error)

// UpdateResult summarises a refresh run. The CLI prints it; tests
// assert on the field values.
type UpdateResult struct {
	// Snapshot is the merged result the caller should hand to a
	// Store. Empty Records means every requested ecosystem
	// returned zero records (probably a server glitch); callers
	// can decide whether to write it or keep the previous local
	// snapshot.
	Snapshot Snapshot
	// PerEcosystem reports the record count produced by each
	// ecosystem so the CLI can show "npm: 1234 records, PyPI:
	// 567 records" rather than a single total.
	PerEcosystem []EcosystemResult
}

// EcosystemResult is the per-ecosystem detail in UpdateResult.
type EcosystemResult struct {
	Ecosystem    string
	RecordsKept  int
	DownloadedAt time.Time
	BytesRead    int64
}

// Update downloads OSV dumps for the requested ecosystems and
// returns the merged snapshot. The caller is responsible for
// passing the snapshot to a Store; Update does no I/O beyond HTTP
// and import to keep the package testable without filesystem
// side effects.
//
// Update is the single entry point production code (and tests) use
// for refresh. It enforces:
//   - per-request timeout
//   - response size cap
//   - per-ecosystem error short-circuit (one ecosystem's HTTP
//     failure does not poison the others; the function returns the
//     first error)
//
// The HTTP path is opt-in: nothing in the binary calls Update
// unless the user explicitly runs `aguara update` or `aguara check
// --fresh`. Default checks remain offline.
func Update(ctx context.Context, opts UpdateOptions) (*UpdateResult, error) {
	if opts.Importer == nil {
		return nil, fmt.Errorf("intel update: Importer is required (CLI must wire osvimport.ImportFromZip)")
	}
	ecosystems := opts.Ecosystems
	if len(ecosystems) == 0 {
		ecosystems = []string{EcosystemNPM, EcosystemPyPI}
	}
	// Canonicalise before building URLs. OSV's GCS bucket keys
	// are case-sensitive (`PyPI/all.zip`, not `pypi/all.zip`),
	// so a user passing `--ecosystem pypi` would otherwise hit a
	// 404 before the importer's canonicaliser had a chance to
	// normalise the value.
	canonical := make([]string, 0, len(ecosystems))
	for _, raw := range ecosystems {
		c := canonicaliseEcosystemForUpdate(raw)
		if c == "" {
			return nil, fmt.Errorf("intel update: unsupported ecosystem %q (supported: %s)", raw, SupportedEcosystemsHint())
		}
		canonical = append(canonical, c)
	}
	ecosystems = canonical
	urlTmpl := opts.URLTemplate
	if urlTmpl == "" {
		urlTmpl = DefaultOSVURLTemplate
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	merged := Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		GeneratedAt:   now(),
	}
	var per []EcosystemResult

	for _, eco := range ecosystems {
		snap, body, err := fetchAndImport(ctx, client, urlTmpl, eco, now(), opts.Importer)
		if err != nil {
			return nil, fmt.Errorf("intel update: %s: %w", eco, err)
		}
		merged.Sources = append(merged.Sources, snap.Sources...)
		merged.Records = append(merged.Records, snap.Records...)
		per = append(per, EcosystemResult{
			Ecosystem:    eco,
			RecordsKept:  len(snap.Records),
			DownloadedAt: now(),
			BytesRead:    body,
		})
		if opts.Stderr != nil {
			fmt.Fprintf(opts.Stderr, "intel update: %s -> %d records (%d bytes)\n",
				eco, len(snap.Records), body)
		}
	}

	dedupeSources(&merged)
	sortRecords(&merged)

	return &UpdateResult{Snapshot: merged, PerEcosystem: per}, nil
}

// fetchAndImport downloads a single ecosystem dump and runs the
// importer over it. Returns the snapshot plus the number of bytes
// read so the per-ecosystem progress line is honest about what
// crossed the network.
func fetchAndImport(ctx context.Context, client *http.Client, urlTmpl, ecosystem string, generatedAt time.Time, importer ImportFunc) (Snapshot, int64, error) {
	url := fmt.Sprintf(urlTmpl, ecosystem)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aguara-update/1.0 (+https://github.com/garagon/aguara)")

	resp, err := client.Do(req)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, 0, fmt.Errorf("http %d %s", resp.StatusCode, resp.Status)
	}

	limited := io.LimitReader(resp.Body, MaxHTTPBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("read body: %w", err)
	}
	if int64(len(data)) > MaxHTTPBodyBytes {
		return Snapshot{}, 0, fmt.Errorf("response %d bytes exceeds cap %d", len(data), MaxHTTPBodyBytes)
	}

	r := bytes.NewReader(data)
	snap, err := importer(r, int64(len(data)), []string{ecosystem}, generatedAt)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("import: %w", err)
	}
	return snap, int64(len(data)), nil
}

// canonicaliseEcosystemForUpdate maps aliases ("pypi", "Python",
// "rust", "java", "dotnet", ...) onto the canonical OSV bucket key.
// Returns "" for unsupported inputs so Update can fail loud rather
// than 404 on a wrongly-cased URL.
//
// Delegates to the registry in ecosystem.go; this thin wrapper
// stays so the update path keeps a named function for grep-discovery
// and so callers reading the file can see where the CLI-level
// alias resolution happens before the URL is built.
//
// The default ecosystem list ([npm, PyPI]) is intentionally NOT
// widened to all 8 in this PR. The embedded snapshot still ships
// only npm + PyPI; flipping the update default before the embedded
// snapshot covers the new ecosystems would create an asymmetric
// experience (`aguara update` pulls 8 buckets but `aguara check`
// has embedded matches for 2). The default flip lands in the
// release PR that regenerates the embedded snapshot.
func canonicaliseEcosystemForUpdate(raw string) string {
	return CanonicaliseEcosystem(raw)
}

// dedupeSources collapses the merged Sources slice to one entry
// per (Name, Kind, URL) so the rendered status output does not
// repeat identical source rows. Order is preserved.
func dedupeSources(snap *Snapshot) {
	if len(snap.Sources) <= 1 {
		return
	}
	seen := make(map[string]struct{}, len(snap.Sources))
	out := snap.Sources[:0]
	for _, src := range snap.Sources {
		key := strings.Join([]string{src.Name, string(src.Kind), src.URL}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, src)
	}
	snap.Sources = out
}

// sortRecords keeps the merged snapshot's record ordering stable
// across runs (ecosystem, name, ID). Matches the importer's order
// so a downstream diff between an embedded and a freshly-fetched
// snapshot does not churn on ordering alone.
func sortRecords(snap *Snapshot) {
	sort.SliceStable(snap.Records, func(i, j int) bool {
		a, b := snap.Records[i], snap.Records[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
}
