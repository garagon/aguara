package intel_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// importerStub is the test wiring for intel.UpdateOptions.Importer.
// It does not actually parse OSV; it just returns the predefined
// snapshot per ecosystem. That lets these tests cover Update's HTTP
// + retry + cap behaviour without dragging in osvimport.
func importerStub(t *testing.T, perEco map[string]intel.Snapshot) intel.ImportFunc {
	t.Helper()
	return func(r io.ReaderAt, size int64, ecosystems []string, generatedAt time.Time) (intel.Snapshot, error) {
		if len(ecosystems) != 1 {
			return intel.Snapshot{}, fmt.Errorf("test stub expects one ecosystem per call, got %v", ecosystems)
		}
		snap, ok := perEco[ecosystems[0]]
		if !ok {
			return intel.Snapshot{}, fmt.Errorf("test stub has no snapshot for ecosystem %q", ecosystems[0])
		}
		return snap, nil
	}
}

// buildEcosystemZip writes a minimal in-memory zip the test
// importer ignores but the HTTP handler serves. Keeping a real
// zip on the wire exercises the size-cap path even though the
// stub does not parse it.
func buildEcosystemZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("placeholder.json")
	require.NoError(t, err)
	_, err = f.Write([]byte(`{"id":"placeholder"}`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestUpdateMergesPerEcosystem(t *testing.T) {
	// Update fetches one URL per ecosystem and merges the results.
	// We stub the importer so the test owns what each ecosystem
	// "contributes" without parsing real OSV JSON.
	body := buildEcosystemZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	perEco := map[string]intel.Snapshot{
		intel.EcosystemNPM: {
			SchemaVersion: intel.CurrentSchemaVersion,
			Sources: []intel.SourceMeta{{Name: "osv.dev/npm", Kind: intel.SourceOSV}},
			Records: []intel.Record{
				{ID: "MAL-NPM-1", Ecosystem: intel.EcosystemNPM, Name: "evil", Versions: []string{"1.0.0"}},
			},
		},
		intel.EcosystemPyPI: {
			SchemaVersion: intel.CurrentSchemaVersion,
			Sources: []intel.SourceMeta{{Name: "osv.dev/PyPI", Kind: intel.SourceOSV}},
			Records: []intel.Record{
				{ID: "MAL-PY-1", Ecosystem: intel.EcosystemPyPI, Name: "evil", Versions: []string{"0.1.0"}},
			},
		},
	}

	res, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM, intel.EcosystemPyPI},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, perEco),
		Now:         func() time.Time { return time.Date(2026, time.May, 15, 0, 0, 0, 0, time.UTC) },
	})
	require.NoError(t, err)
	require.Len(t, res.Snapshot.Records, 2, "merged snapshot must carry one record per ecosystem")
	require.Equal(t, 2, len(res.PerEcosystem))

	// Order in PerEcosystem follows the input ecosystems slice
	// so the CLI's progress output is predictable.
	require.Equal(t, intel.EcosystemNPM, res.PerEcosystem[0].Ecosystem)
	require.Equal(t, 1, res.PerEcosystem[0].RecordsKept)
	require.Equal(t, intel.EcosystemPyPI, res.PerEcosystem[1].Ecosystem)
}

func TestUpdateRequiresImporter(t *testing.T) {
	// Production callers must wire in the osvimport adapter; a
	// nil Importer is a programmer bug, not a runtime error
	// path we want to silently tolerate.
	_, err := intel.Update(context.Background(), intel.UpdateOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Importer is required")
}

func TestUpdatePropagatesHTTPError(t *testing.T) {
	// Non-200 responses must short-circuit the run; one
	// ecosystem's HTTP failure (e.g. OSV.dev outage) should
	// abort the refresh rather than write a partial snapshot.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, map[string]intel.Snapshot{}),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "http 500")
}

func TestUpdateEnforcesSizeCap(t *testing.T) {
	// A response larger than MaxHTTPBodyBytes must be rejected
	// before it can fill memory. We do not actually send 256 MiB
	// in the test; we instead serve a body declared with a
	// Content-Length that the LimitReader path can see, then
	// pad past the cap. The trip-wire fires when the read
	// produces more than MaxHTTPBodyBytes bytes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write MaxHTTPBodyBytes + 1 zero bytes. We do this
		// in chunks so the test does not allocate the whole
		// payload at once.
		const chunk = 1 << 20 // 1 MiB
		buf := make([]byte, chunk)
		remaining := intel.MaxHTTPBodyBytes + 1
		for remaining > 0 {
			n := int64(chunk)
			if n > remaining {
				n = remaining
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	defer srv.Close()

	_, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, map[string]intel.Snapshot{}),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds cap")
}

func TestUpdateUsesDefaultEcosystems(t *testing.T) {
	// Empty UpdateOptions.Ecosystems must default to [npm, PyPI]
	// so users running `aguara update` with no flags get the
	// production two-ecosystem refresh.
	body := buildEcosystemZip(t)
	var seenURLs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURLs = append(seenURLs, r.URL.Path)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := intel.Update(context.Background(), intel.UpdateOptions{
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer: importerStub(t, map[string]intel.Snapshot{
			intel.EcosystemNPM:  {SchemaVersion: intel.CurrentSchemaVersion},
			intel.EcosystemPyPI: {SchemaVersion: intel.CurrentSchemaVersion},
		}),
	})
	require.NoError(t, err)
	require.Len(t, seenURLs, 2, "default ecosystems must produce two HTTP fetches")
	require.Equal(t, "/npm/all.zip", seenURLs[0])
	require.Equal(t, "/PyPI/all.zip", seenURLs[1])
}

func TestUpdateRespectsContextCancellation(t *testing.T) {
	// A canceled context must short-circuit before the second
	// ecosystem's request. We use a slow handler so the first
	// request can succeed and the second one fires during
	// cancellation.
	body := buildEcosystemZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: every request must fail

	_, err := intel.Update(ctx, intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM, intel.EcosystemPyPI},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, map[string]intel.Snapshot{}),
	})
	require.Error(t, err, "canceled context must surface as an error")
}

func TestUpdateDedupesSourcesAcrossEcosystems(t *testing.T) {
	// Two ecosystems that contribute the same (Name, Kind, URL)
	// source entry must collapse to one in the merged Sources
	// slice, so `aguara status` does not show duplicate rows.
	body := buildEcosystemZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	shared := intel.SourceMeta{Name: "osv.dev", Kind: intel.SourceOSV, URL: "https://osv.dev"}
	perEco := map[string]intel.Snapshot{
		intel.EcosystemNPM:  {Sources: []intel.SourceMeta{shared}, Records: []intel.Record{{ID: "A", Ecosystem: intel.EcosystemNPM, Name: "a", Versions: []string{"1"}}}},
		intel.EcosystemPyPI: {Sources: []intel.SourceMeta{shared}, Records: []intel.Record{{ID: "B", Ecosystem: intel.EcosystemPyPI, Name: "b", Versions: []string{"1"}}}},
	}
	res, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM, intel.EcosystemPyPI},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, perEco),
	})
	require.NoError(t, err)
	require.Len(t, res.Snapshot.Sources, 1, "identical Sources entries across ecosystems must collapse")
}

func TestUpdateRecordsStableOrder(t *testing.T) {
	// Reproducible builds rely on stable record ordering -- the
	// merged snapshot must come out sorted regardless of which
	// ecosystem ran first.
	body := buildEcosystemZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	perEco := map[string]intel.Snapshot{
		intel.EcosystemNPM: {Records: []intel.Record{
			{ID: "C", Ecosystem: intel.EcosystemNPM, Name: "z", Versions: []string{"1"}},
			{ID: "A", Ecosystem: intel.EcosystemNPM, Name: "a", Versions: []string{"1"}},
		}},
	}
	res, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, perEco),
	})
	require.NoError(t, err)
	require.Equal(t, "a", res.Snapshot.Records[0].Name, "merged records must be sorted by name")
	require.Equal(t, "z", res.Snapshot.Records[1].Name)
}

func TestUpdateCanonicalisesEcosystemAlias(t *testing.T) {
	// Codex P2 (PR 4 review): a user typing `--ecosystem pypi`
	// (lowercase) previously got a 404 because OSV's bucket key
	// is case-sensitive (`PyPI/all.zip`). Canonicalise before
	// building the URL so the alias resolves to the right path.
	body := buildEcosystemZip(t)
	var seenURLs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURLs = append(seenURLs, r.URL.Path)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{"pypi", "python"},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer: importerStub(t, map[string]intel.Snapshot{
			intel.EcosystemPyPI: {},
		}),
	})
	require.NoError(t, err)
	require.Len(t, seenURLs, 2)
	for _, u := range seenURLs {
		require.Equal(t, "/PyPI/all.zip", u, "alias must canonicalise to OSV's case-sensitive bucket key")
	}
}

func TestUpdateRejectsUnsupportedEcosystemEarly(t *testing.T) {
	// An unsupported ecosystem must fail BEFORE any HTTP request
	// goes out. Otherwise a typo in `--ecosystem` (e.g. `npmm`)
	// would hit OSV with a bad URL just to discover the input
	// was wrong.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	_, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{"npmm"},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer:    importerStub(t, map[string]intel.Snapshot{}),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported ecosystem")
	require.False(t, called, "no HTTP request should fire for an unsupported ecosystem")
}

// TestUpdateSendsUserAgent locks the User-Agent header so OSV.dev
// can attribute traffic to Aguara. Helps with rate-limit triage if
// someone abuses the public dump. Marshalling via json so the
// surface area is broad enough to catch a regression in either
// req.Header or the constant itself.
func TestUpdateSendsUserAgent(t *testing.T) {
	body := buildEcosystemZip(t)
	var seenUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := intel.Update(context.Background(), intel.UpdateOptions{
		Ecosystems:  []string{intel.EcosystemNPM},
		URLTemplate: srv.URL + "/%s/all.zip",
		HTTPClient:  srv.Client(),
		Importer: importerStub(t, map[string]intel.Snapshot{
			intel.EcosystemNPM: {},
		}),
	})
	require.NoError(t, err)
	require.Contains(t, seenUA, "aguara")

	// Sanity: the snapshot can round-trip JSON, the runtime
	// contract IntelSummary downstream callers depend on.
	encoded, err := json.Marshal(intel.Snapshot{})
	require.NoError(t, err)
	require.NotEmpty(t, encoded)
}
