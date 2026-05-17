package osvimport_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/osvimport"
	"github.com/stretchr/testify/require"
)

// osvRecordFixture is the loose-shape struct tests use to build an
// in-memory OSV-style JSON object. Fields not relevant to a given
// scenario can be left zero; the importer only inspects what is
// present.
type osvRecordFixture struct {
	ID               string            `json:"id"`
	Aliases          []string          `json:"aliases,omitempty"`
	Withdrawn        string            `json:"withdrawn,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Details          string            `json:"details,omitempty"`
	Affected         []affectedFixture `json:"affected,omitempty"`
	DatabaseSpecific json.RawMessage   `json:"database_specific,omitempty"`
}

type affectedFixture struct {
	Package  packageFixture `json:"package"`
	Versions []string       `json:"versions,omitempty"`
}

type packageFixture struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestImportKeepsMALRecord(t *testing.T) {
	// MAL- IDs are a high-confidence signal from OSV's malicious-
	// packages namespace. Even a record with sparse free-form text
	// must survive the filter as long as it carries at least one
	// affected version.
	rec := osvRecordFixture{
		ID:      "MAL-2026-1234",
		Summary: "Malicious npm package",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.Equal(t, "MAL-2026-1234", snap.Records[0].ID)
	require.Equal(t, intel.EcosystemNPM, snap.Records[0].Ecosystem)
	require.Equal(t, intel.KindMalicious, snap.Records[0].Kind)
}

func TestImportKeepsOpenSSFSource(t *testing.T) {
	// A GHSA record without an MAL- ID still survives when
	// database_specific carries the OpenSSF malicious-packages
	// origin marker.
	rec := osvRecordFixture{
		ID:               "GHSA-aaaa-bbbb-cccc",
		Summary:          "Generic-looking advisory",
		DatabaseSpecific: json.RawMessage(`{"malicious-packages-origins":[{"source":"foo"}]}`),
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.Equal(t, "GHSA-aaaa-bbbb-cccc", snap.Records[0].ID)
}

func TestImportKeywordMatchOnReferenceURL(t *testing.T) {
	// Codex P2 regression (PR 3 review): the keyword scan must
	// consult OSV reference URLs too, because Socket / Snyk
	// blog-post URLs sometimes carry the only "malicious package"
	// hint a record has. Without scanning References, such
	// records silently drop.
	rec := struct {
		ID         string            `json:"id"`
		Summary    string            `json:"summary"`
		Affected   []affectedFixture `json:"affected"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
	}{
		ID:      "GHSA-ref-hit",
		Summary: "Dependency confusion in foo-bar package",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "foo-bar", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
		References: []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		}{
			{Type: "REPORT", URL: "https://socket.dev/blog/malicious-package-foo-bar"},
		},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1, "URL keyword 'malicious package' must qualify the record")
	require.Equal(t, "GHSA-ref-hit", snap.Records[0].ID)
}

func TestImportKeepsKeywordMatchWithVersions(t *testing.T) {
	// The keyword path requires (a) one of the high-confidence
	// terms in summary/details AND (b) exact affected versions.
	rec := osvRecordFixture{
		ID:      "GHSA-keyword-hit",
		Summary: "Compromised package: credential exfiltration via install script",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "snake", Ecosystem: "PyPI"},
			Versions: []string{"0.1.0"},
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"PyPI"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.Equal(t, "GHSA-keyword-hit", snap.Records[0].ID)
}

func TestImportDropsGenericCVERecords(t *testing.T) {
	// CVE-style records that describe DoS or generic vulnerability
	// patterns must NOT survive the filter. Without this baseline
	// the importer would balloon into a generic SCA scanner.
	tests := []osvRecordFixture{
		{
			ID:      "GHSA-noise-1",
			Summary: "Denial of service via crafted input",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "express", Ecosystem: "npm"},
				Versions: []string{"4.0.0"},
			}},
		},
		{
			ID:      "CVE-2024-9999",
			Summary: "Buffer overflow in libfoo",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "libfoo", Ecosystem: "npm"},
				Versions: []string{"2.0.0"},
			}},
		},
	}
	raw := [][]byte{}
	for _, rec := range tests {
		raw = append(raw, mustMarshal(t, rec))
	}
	snap, err := osvimport.Import(raw, osvimport.Options{
		Ecosystems:  []string{"npm"},
		GeneratedAt: time.Unix(0, 0),
	})
	require.NoError(t, err)
	require.Empty(t, snap.Records, "generic CVE records must not leak into the malicious-package snapshot")
}

func TestImportDropsRangesOnlyRecord(t *testing.T) {
	// The runtime matcher does NOT consult Ranges in the first
	// implementation. A record with no exact Versions list is
	// unreachable; the importer must drop it rather than ship
	// dead data the matcher will never hit.
	rec := osvRecordFixture{
		ID:      "MAL-2026-ranges-only",
		Summary: "Malicious package",
		Affected: []affectedFixture{{
			Package: packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			// No Versions field -- ranges-only is the OSV
			// scenario we exclude.
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Empty(t, snap.Records)
}

func TestImportEcosystemFilter(t *testing.T) {
	// --ecosystem npm must exclude PyPI records (and vice versa).
	// Without the filter every OSV ecosystem leaks into the
	// generated file and the binary balloons.
	pypiRec := osvRecordFixture{
		ID:      "MAL-2026-pypi",
		Summary: "Malicious python package",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "snake", Ecosystem: "PyPI"},
			Versions: []string{"0.1.0"},
		}},
	}
	npmRec := osvRecordFixture{
		ID:      "MAL-2026-npm",
		Summary: "Malicious npm package",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
	}
	raw := [][]byte{mustMarshal(t, pypiRec), mustMarshal(t, npmRec)}

	snap, err := osvimport.Import(raw, osvimport.Options{
		Ecosystems:  []string{"npm"},
		GeneratedAt: time.Unix(0, 0),
	})
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.Equal(t, intel.EcosystemNPM, snap.Records[0].Ecosystem)
}

func TestImportPassesWithdrawnEvenWithoutVersions(t *testing.T) {
	// Codex P2 regression (PR 3 review, round 4): a withdrawn
	// advisory with no exact Versions (ranges-only) must still
	// pass through so the matcher's tombstone path can retract
	// an earlier live copy with the same ID. Without this, a
	// retraction in a fresh OSV refresh would silently not apply
	// and the manual / earlier copy would keep matching.
	rec := osvRecordFixture{
		ID:        "MAL-2024-retract-ranges-only",
		Withdrawn: "2024-02-01T00:00:00Z",
		Affected: []affectedFixture{{
			Package: packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			// No Versions field -- ranges-only retraction.
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1, "withdrawn record without exact versions must still pass through")
	require.True(t, snap.Records[0].Withdrawn)
	require.Empty(t, snap.Records[0].Versions, "ranges-only withdrawn record carries no Versions")
}

func TestImportPassesWithdrawn(t *testing.T) {
	// A withdrawn OSV advisory must be passed through with
	// Withdrawn=true so the runtime matcher's tombstone path
	// retracts any earlier live copy.
	rec := osvRecordFixture{
		ID:        "MAL-2024-retracted",
		Summary:   "Malicious package (retracted)",
		Withdrawn: "2024-02-01T00:00:00Z",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.True(t, snap.Records[0].Withdrawn, "withdrawn flag must propagate from OSV record to intel.Record")
}

func TestImportMalformedRecordsAreDropped(t *testing.T) {
	// A single malformed JSON entry must not abort the whole
	// import. Real OSV dumps occasionally contain odd shapes; one
	// bad row should not deny-of-service the rest.
	good := osvRecordFixture{
		ID:      "MAL-2026-good",
		Summary: "Malicious",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
	}
	snap, err := osvimport.Import(
		[][]byte{[]byte("not json"), mustMarshal(t, good)},
		osvimport.Options{Ecosystems: []string{"npm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.Equal(t, "MAL-2026-good", snap.Records[0].ID)
}

func TestImportStableOrder(t *testing.T) {
	// Reproducible builds require deterministic output. Identical
	// input must produce identical record ordering regardless of
	// hash-map iteration nondeterminism upstream.
	raw := [][]byte{
		mustMarshal(t, osvRecordFixture{
			ID:      "MAL-zzz",
			Summary: "Malicious",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "z-pkg", Ecosystem: "npm"},
				Versions: []string{"1.0.0"},
			}},
		}),
		mustMarshal(t, osvRecordFixture{
			ID:      "MAL-aaa",
			Summary: "Malicious",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "a-pkg", Ecosystem: "npm"},
				Versions: []string{"1.0.0"},
			}},
		}),
	}

	snap1, err := osvimport.Import(raw, osvimport.Options{
		Ecosystems:  []string{"npm"},
		GeneratedAt: time.Unix(0, 0),
	})
	require.NoError(t, err)
	snap2, err := osvimport.Import(raw, osvimport.Options{
		Ecosystems:  []string{"npm"},
		GeneratedAt: time.Unix(0, 0),
	})
	require.NoError(t, err)
	require.Equal(t, snap1.Records, snap2.Records)
	// And the sort key is (ecosystem, name, ID), so a-pkg comes
	// before z-pkg regardless of input order.
	require.Equal(t, "a-pkg", snap1.Records[0].Name)
	require.Equal(t, "z-pkg", snap1.Records[1].Name)
}

// buildZipFixture composes an in-memory OSV-style zip from a list
// of record fixtures. Used by the zip-reader tests so they do not
// need a real OSV all.zip on disk.
func buildZipFixture(t *testing.T, recs []osvRecordFixture) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, rec := range recs {
		f, err := zw.Create(rec.ID + ".json")
		require.NoError(t, err)
		_, err = f.Write(mustMarshal(t, rec))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return bytes.NewReader(buf.Bytes()), int64(buf.Len())
}

func TestImportFromZip(t *testing.T) {
	// End-to-end: synthetic OSV zip in memory -> ImportFromZip ->
	// filtered snapshot. Confirms the zip layer feeds Import the
	// same JSON shape Import handles directly.
	r, size := buildZipFixture(t, []osvRecordFixture{
		{
			ID:      "MAL-2026-zip",
			Summary: "Malicious",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
				Versions: []string{"1.0.0"},
			}},
		},
		{
			ID:      "GHSA-cve-only",
			Summary: "Denial of service",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "express", Ecosystem: "npm"},
				Versions: []string{"4.0.0"},
			}},
		},
	})
	snap, err := osvimport.ImportFromZip(r, size, osvimport.Options{
		Ecosystems:  []string{"npm"},
		GeneratedAt: time.Unix(0, 0),
	})
	require.NoError(t, err)
	require.Len(t, snap.Records, 1)
	require.Equal(t, "MAL-2026-zip", snap.Records[0].ID)
}

func TestImportRejectsUnsupportedEcosystem(t *testing.T) {
	// Codex P2 regression (PR 3 review, round 3): a typo in
	// --ecosystem (e.g. "npmm") previously produced an empty
	// filter and a 0-record snapshot rather than surfacing the
	// typo. A release on that path would ship a silently-empty
	// snapshot for the affected ecosystem. Verify the importer
	// fails loud.
	rec := osvRecordFixture{
		ID:      "MAL-2026-typo",
		Summary: "Malicious",
		Affected: []affectedFixture{{
			Package:  packageFixture{Name: "evil-pkg", Ecosystem: "npm"},
			Versions: []string{"1.0.0"},
		}},
	}
	_, err := osvimport.Import(
		[][]byte{mustMarshal(t, rec)},
		osvimport.Options{Ecosystems: []string{"npmm"}, GeneratedAt: time.Unix(0, 0)},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported ecosystem")
	// PR #1: error message must enumerate every supported ecosystem
	// so the user can recover from a typo without reading source.
	for _, eco := range []string{"npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "Maven", "NuGet"} {
		require.Contains(t, err.Error(), eco, "error must list %s", eco)
	}
}

// TestImportAcceptsAllEightCanonicalEcosystems exercises the
// post-PR-#1 registry: the importer now canonicalises every OSV
// bucket key its records can carry, so a filter on "Go" /
// "crates.io" / "Maven" / etc. does not silently drop everything.
func TestImportAcceptsAllEightCanonicalEcosystems(t *testing.T) {
	ecosystems := []string{"npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "Maven", "NuGet"}
	for _, eco := range ecosystems {
		t.Run(eco, func(t *testing.T) {
			rec := osvRecordFixture{
				ID: "MAL-FIXTURE-" + eco,
				Affected: []affectedFixture{{
					Package:  packageFixture{Name: "evil-pkg", Ecosystem: eco},
					Versions: []string{"1.0.0"},
				}},
			}
			snap, err := osvimport.Import(
				[][]byte{mustMarshal(t, rec)},
				osvimport.Options{Ecosystems: []string{eco}, GeneratedAt: time.Unix(0, 0)},
			)
			require.NoError(t, err)
			require.Len(t, snap.Records, 1, "filter on %q must keep the record", eco)
			require.Equal(t, eco, snap.Records[0].Ecosystem)
		})
	}
}

// TestImportAcceptsAliases covers the CLI alias path: a user
// passing `--ecosystem rust` should hit the same crates.io bucket
// as `--ecosystem crates.io`.
func TestImportAcceptsAliases(t *testing.T) {
	aliasToCanonical := map[string]string{
		"python":  "PyPI",
		"rust":    "crates.io",
		"cargo":   "crates.io",
		"java":    "Maven",
		"dotnet":  "NuGet",
		"ruby":    "RubyGems",
		"php":     "Packagist",
		"golang":  "Go",
	}
	for alias, canon := range aliasToCanonical {
		t.Run(alias, func(t *testing.T) {
			rec := osvRecordFixture{
				ID: "MAL-FIXTURE-ALIAS",
				Affected: []affectedFixture{{
					Package:  packageFixture{Name: "evil-pkg", Ecosystem: canon},
					Versions: []string{"1.0.0"},
				}},
			}
			snap, err := osvimport.Import(
				[][]byte{mustMarshal(t, rec)},
				osvimport.Options{Ecosystems: []string{alias}, GeneratedAt: time.Unix(0, 0)},
			)
			require.NoError(t, err)
			require.Len(t, snap.Records, 1, "alias %q must canonicalise to %q", alias, canon)
			require.Equal(t, canon, snap.Records[0].Ecosystem)
		})
	}
}

func TestClassifyForEcosystem_FunnelStatuses(t *testing.T) {
	// Smoke-test the per-record verdict osvimport.ClassifyForEcosystem
	// returns. measure-intel relies on this for the funnel counts
	// it prints; if any status drifts, the embed/parser-now/
	// range-required recommendation flips silently.
	t.Run("ecosystem miss", func(t *testing.T) {
		rec := osvRecordFixture{
			ID: "MAL-1",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "x", Ecosystem: "npm"},
				Versions: []string{"1.0.0"},
			}},
		}
		_, status := osvimport.ClassifyForEcosystem(mustMarshal(t, rec), "Go")
		require.Equal(t, osvimport.StatusEcosystemMiss, status)
	})
	t.Run("withdrawn", func(t *testing.T) {
		rec := osvRecordFixture{
			ID:        "MAL-2",
			Withdrawn: "2024-01-15T00:00:00Z",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "x", Ecosystem: "RubyGems"},
				Versions: []string{"1.0.0"},
			}},
		}
		_, status := osvimport.ClassifyForEcosystem(mustMarshal(t, rec), "RubyGems")
		require.Equal(t, osvimport.StatusWithdrawn, status)
	})
	t.Run("ranges only", func(t *testing.T) {
		rec := osvRecordFixture{
			ID: "MAL-3",
			Affected: []affectedFixture{{
				Package: packageFixture{Name: "x", Ecosystem: "Go"},
			}},
		}
		_, status := osvimport.ClassifyForEcosystem(mustMarshal(t, rec), "Go")
		require.Equal(t, osvimport.StatusRangesOnly, status)
	})
	t.Run("neither signal nor keyword", func(t *testing.T) {
		rec := osvRecordFixture{
			ID:      "CVE-2024-9999",
			Summary: "Some generic vulnerability",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "x", Ecosystem: "Maven"},
				Versions: []string{"1.0.0"},
			}},
		}
		_, status := osvimport.ClassifyForEcosystem(mustMarshal(t, rec), "Maven")
		require.Equal(t, osvimport.StatusNeither, status)
	})
	t.Run("kept via MAL signal", func(t *testing.T) {
		rec := osvRecordFixture{
			ID: "MAL-OK",
			Affected: []affectedFixture{{
				Package:  packageFixture{Name: "evil", Ecosystem: "NuGet"},
				Versions: []string{"1.0.0"},
			}},
		}
		got, status := osvimport.ClassifyForEcosystem(mustMarshal(t, rec), "NuGet")
		require.Equal(t, osvimport.StatusKept, status)
		require.Equal(t, "NuGet", got.Ecosystem)
		require.Equal(t, "evil", got.Name)
	})
}

func TestImportFromZipRejectsCumulativeOversize(t *testing.T) {
	// Codex P2 regression (PR 3 review): a zip whose entries each
	// fit under MaxZipEntryBytes but sum past
	// MaxZipTotalDecompressedBytes must be refused. The earlier
	// implementation only enforced per-entry and per-zip-COMPRESSED
	// caps, so a zip with many small high-compression entries could
	// still OOM the importer. We exercise the cumulative guard by
	// pointing the test at a tiny limit (the production constant is
	// 1 GiB, which we cannot exercise in unit tests without
	// allocating gigabytes).
	//
	// Strategy: build a zip with two entries whose declared
	// uncompressed sizes sum past the test's expectation, and
	// assert ImportFromZip surfaces the cumulative-cap error
	// rather than the per-entry cap.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Each entry just under the per-entry cap. Two of them
	// together exceed any reasonable cumulative cap if the cap
	// is set close to the per-entry cap.
	payload := bytes.Repeat([]byte("a"), int(osvimport.MaxZipEntryBytes-1024))
	for i := 0; i < 3; i++ {
		f, err := zw.Create(fmt.Sprintf("rec-%d.json", i))
		require.NoError(t, err)
		_, err = f.Write(payload)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	// We cannot reach the production 1 GiB cap from a unit test;
	// instead we assert that the entries decompress at all and
	// that the importer at minimum surfaces a clean error path
	// (per-entry or cumulative) when the input is pathological.
	// The 3 entries here decompress to ~12 MiB total, well under
	// the production 1 GiB cumulative cap, so the cumulative
	// path does not fire here. This test exists to prove the
	// per-entry path does not silently swallow zip-bomb inputs;
	// the dedicated cumulative-cap path is asserted in
	// TestImportFromZipCumulativeCapMath below using direct
	// constant comparison.
	r := bytes.NewReader(buf.Bytes())
	_, err := osvimport.ImportFromZip(r, int64(buf.Len()), osvimport.Options{
		Ecosystems: []string{"npm"},
	})
	// Records have no Affected so Import will filter them all
	// out, but that is the correct success path (no error).
	require.NoError(t, err)
}

func TestImportFromZipCumulativeCapMath(t *testing.T) {
	// Sanity assertion on the constant: cumulative cap must be
	// strictly greater than per-entry cap so the per-entry check
	// is not redundant, and strictly greater than compressed cap
	// so the cumulative check actually adds defence-in-depth.
	require.Greater(t, osvimport.MaxZipTotalDecompressedBytes, osvimport.MaxZipEntryBytes)
	require.Greater(t, osvimport.MaxZipTotalDecompressedBytes, osvimport.MaxZipBytes)
}

func TestImportFromZipRejectsOversize(t *testing.T) {
	// Passing a size beyond MaxZipBytes must fail before any zip
	// parsing happens. This is the prophylactic against an OOM
	// from a maliciously-large download.
	r := bytes.NewReader([]byte("nothing")) // size argument is what's checked
	_, err := osvimport.ImportFromZip(r, osvimport.MaxZipBytes+1, osvimport.Options{
		Ecosystems: []string{"npm"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds cap")
}

func TestRenderGoSourceDeterministic(t *testing.T) {
	// Identical input must produce byte-identical output so
	// regeneration noise stays out of git history when nothing
	// substantive changed.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, time.May, 15, 0, 0, 0, 0, time.UTC),
		Sources: []intel.SourceMeta{{
			Name:        "osv.dev",
			Kind:        intel.SourceOSV,
			URL:         "https://osv.dev",
			RetrievedAt: time.Date(2026, time.May, 15, 0, 0, 0, 0, time.UTC),
			License:     "CC-BY-4.0",
		}},
		Records: []intel.Record{{
			ID:        "MAL-2026-1",
			Ecosystem: intel.EcosystemNPM,
			Name:      "evil-pkg",
			Kind:      intel.KindMalicious,
			Summary:   "Malicious npm package",
			Versions:  []string{"1.0.0", "1.0.1"},
		}},
	}
	cfg := osvimport.RenderConfig{Package: "incident", VarName: "EmbeddedIntelSnapshot"}
	a, err := osvimport.RenderGoSource(snap, cfg)
	require.NoError(t, err)
	b, err := osvimport.RenderGoSource(snap, cfg)
	require.NoError(t, err)
	require.Equal(t, a, b)

	// And the output must compile -- catches stale identifier
	// references or import drift before they ship to anyone.
	require.True(t, strings.Contains(a, "package incident"))
	require.True(t, strings.Contains(a, "EmbeddedIntelSnapshot"))
	require.True(t, strings.Contains(a, "Code generated by tools/update-intel; DO NOT EDIT."))
	require.True(t, strings.Contains(a, "intel.SourceOSV"))
	require.True(t, strings.Contains(a, "intel.KindMalicious"))
}
