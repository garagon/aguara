package main

import (
	"reflect"
	"strings"
	"testing"
)

// osvFixture is a static OSV /v1/query response for npm
// dev-env-bootstrapper. It carries an exact version, a SEMVER range,
// an alias, a campaign marker URL, and a SECOND affected package to
// prove the parser filters affected entries to the queried package.
const osvFixture = `{
  "vulns": [
    {
      "id": "MAL-2026-4277",
      "aliases": ["GHSA-aaaa-bbbb-cccc"],
      "affected": [
        {
          "package": {"name": "dev-env-bootstrapper", "ecosystem": "npm"},
          "versions": ["1.0.12"],
          "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.13"}]}
          ]
        },
        {
          "package": {"name": "unrelated-pkg", "ecosystem": "npm"},
          "versions": ["9.9.9"]
        }
      ],
      "references": [
        {"url": "https://ddjidd564.github.io/defi-security-best-practices/payload.js"}
      ]
    }
  ]
}`

func TestParseOSVQueryResponse(t *testing.T) {
	got, err := parseOSVQueryResponse([]byte(osvFixture), "npm", "dev-env-bootstrapper")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !reflect.DeepEqual(got.ids, []string{"MAL-2026-4277"}) {
		t.Errorf("ids = %v, want [MAL-2026-4277]", got.ids)
	}
	// Only the queried package's version, not the sibling's 9.9.9.
	if !reflect.DeepEqual(got.exactVersions, []string{"1.0.12"}) {
		t.Errorf("exactVersions = %v, want [1.0.12]", got.exactVersions)
	}
	if !reflect.DeepEqual(got.aliases, []string{"GHSA-aaaa-bbbb-cccc"}) {
		t.Errorf("aliases = %v, want [GHSA-aaaa-bbbb-cccc]", got.aliases)
	}
	if len(got.ranges) != 1 {
		t.Fatalf("ranges = %v, want 1 entry", got.ranges)
	}
	wantRange := RangeOut{Type: "SEMVER", Introduced: "0", Fixed: "1.0.13"}
	if got.ranges[0] != wantRange {
		t.Errorf("range = %+v, want %+v", got.ranges[0], wantRange)
	}
	assertContains(t, "ioc markers", got.iocMarkers, "ddjidd564.github.io")
	assertContains(t, "ioc markers", got.iocMarkers, "defi-security-best-practices")
}

func TestParseOSVQueryResponseEmpty(t *testing.T) {
	got, err := parseOSVQueryResponse([]byte(`{}`), "npm", "anything")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.ids) != 0 || len(got.exactVersions) != 0 || len(got.ranges) != 0 {
		t.Errorf("empty response should yield no signals, got %+v", got)
	}
}

func TestParseOSVQueryResponseWithdrawn(t *testing.T) {
	const withdrawnFixture = `{
      "vulns": [
        {
          "id": "MAL-2026-9999",
          "withdrawn": "2026-05-25T00:00:00Z",
          "affected": [
            {"package": {"name": "p", "ecosystem": "npm"}, "versions": ["1.0.0"]}
          ]
        }
      ]
    }`
	got, err := parseOSVQueryResponse([]byte(withdrawnFixture), "npm", "p")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got.withdrawn, []string{"MAL-2026-9999"}) {
		t.Errorf("withdrawn = %v, want [MAL-2026-9999]", got.withdrawn)
	}
	// A retracted advisory's versions must NOT feed the verdict, even
	// though they are present in the record. Otherwise the tool would
	// approve intel from an advisory OSV no longer confirms.
	if len(got.exactVersions) != 0 {
		t.Errorf("exactVersions = %v, want none from a withdrawn advisory", got.exactVersions)
	}
	if len(got.ranges) != 0 {
		t.Errorf("ranges = %v, want none from a withdrawn advisory", got.ranges)
	}
	// The ID is still recorded so the report can surface it.
	if !reflect.DeepEqual(got.ids, []string{"MAL-2026-9999"}) {
		t.Errorf("ids = %v, want the withdrawn id recorded for visibility", got.ids)
	}
}

func TestParseOSVQueryResponseLiveBesideWithdrawn(t *testing.T) {
	// One live advisory (exact 1.0.12) and one withdrawn advisory
	// (exact 9.9.9) for the same package. Only the live version counts.
	const fixture = `{
      "vulns": [
        {
          "id": "MAL-2026-LIVE",
          "affected": [{"package": {"name": "p", "ecosystem": "npm"}, "versions": ["1.0.12"]}]
        },
        {
          "id": "MAL-2026-DEAD",
          "withdrawn": "2026-05-25T00:00:00Z",
          "affected": [{"package": {"name": "p", "ecosystem": "npm"}, "versions": ["9.9.9"]}]
        }
      ]
    }`
	got, err := parseOSVQueryResponse([]byte(fixture), "npm", "p")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got.exactVersions, []string{"1.0.12"}) {
		t.Errorf("exactVersions = %v, want only the live [1.0.12]", got.exactVersions)
	}
	if !reflect.DeepEqual(got.withdrawn, []string{"MAL-2026-DEAD"}) {
		t.Errorf("withdrawn = %v, want [MAL-2026-DEAD]", got.withdrawn)
	}
}

func TestParseOSVQueryResponsePyPINameNormalisation(t *testing.T) {
	// OSV stores the underscore form; we query the hyphen form.
	const fixture = `{
      "vulns": [
        {
          "id": "MAL-2026-1",
          "affected": [
            {"package": {"name": "eth_security_auditor", "ecosystem": "PyPI"}, "versions": ["0.1.0"]}
          ]
        }
      ]
    }`
	got, err := parseOSVQueryResponse([]byte(fixture), "PyPI", "eth-security-auditor")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got.exactVersions, []string{"0.1.0"}) {
		t.Errorf("exactVersions = %v, want [0.1.0] (PEP 503 match)", got.exactVersions)
	}
}

func TestNPMRegistryURLEscaping(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"dev-env-bootstrapper", "https://registry.npmjs.org/dev-env-bootstrapper"},
		{"@scope/pkg", "https://registry.npmjs.org/@scope%2fpkg"},
		{"@org/deep/name", "https://registry.npmjs.org/@org%2fdeep%2fname"},
	}
	for _, tc := range cases {
		if got := npmRegistryURL(tc.name); got != tc.want {
			t.Errorf("npmRegistryURL(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name             string
		hasExact         bool
		hasRanges        bool
		hasOSV           bool
		registryConfirms bool
		wantDisp         string
		wantReady        bool
	}{
		{"exact versions -> ready_exact", true, false, true, false, dispReadyExact, true},
		{"exact plus ranges -> ready_exact", true, true, true, false, dispReadyExact, true},
		// Confirmed malicious but range-only: a real threat, but NOT
		// exact-version-ready. This is the key spec rule (Open Q #4):
		// no manual exact-version intel without exact versions.
		{"ranges only, registry confirms -> ranges_only_confirmed, NOT ready", false, true, true, true, dispRangesConfirmed, false},
		{"ranges only, no confirm -> ranges_only_unconfirmed, NOT ready", false, true, true, false, dispRangesUnconfirmed, false},
		{"osv but no versions/ranges -> hold", false, false, true, false, dispHold, false},
		{"no osv, registry signal -> hold", false, false, false, true, dispHold, false},
		{"nothing -> hold", false, false, false, false, dispHold, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disp, ready, notes := classify(tc.hasExact, tc.hasRanges, tc.hasOSV, tc.registryConfirms)
			if disp != tc.wantDisp {
				t.Errorf("disposition = %q, want %q", disp, tc.wantDisp)
			}
			if ready != tc.wantReady {
				t.Errorf("ready = %v, want %v (notes: %s)", ready, tc.wantReady, notes)
			}
			if ready && disp != dispReadyExact {
				t.Errorf("ManualIntelReady must imply ready_exact, got disp=%q", disp)
			}
			if notes == "" {
				t.Error("notes must never be empty")
			}
		})
	}
}

func TestParseNPMRegistrySecurityHolding(t *testing.T) {
	const body = `{"description":"Security holding package","versions":{"0.0.1-security":{}}}`
	got, err := parseNPMRegistry([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.confirmsMalicious {
		t.Error("security holding package should confirm malicious removal")
	}
}

func TestParseNPMRegistryNormal(t *testing.T) {
	const body = `{"description":"a normal package","versions":{"1.0.0":{},"1.1.0":{"deprecated":"old"}}}`
	got, err := parseNPMRegistry([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.confirmsMalicious {
		t.Error("normal package must not confirm malicious")
	}
	if !strings.Contains(strings.Join(got.signals, " "), "2 published") {
		t.Errorf("signals = %v, want a published-version count", got.signals)
	}
}

func TestParsePyPIRegistryWithVulns(t *testing.T) {
	const body = `{"releases":{"0.1.0":[]},"vulnerabilities":[{"id":"PYSEC-2026-1"}]}`
	got, err := parsePyPIRegistry([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.confirmsMalicious {
		t.Error("a PyPI vulnerability advisory should confirm")
	}
}

func TestParseCratesRegistryYankedDoesNotConfirm(t *testing.T) {
	const body = `{"versions":[{"num":"0.1.0","yanked":true},{"num":"0.1.1","yanked":true}]}`
	got, err := parseCratesRegistry([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.confirmsMalicious {
		t.Error("yanked crates must NOT auto-confirm malicious (conservative)")
	}
	if !strings.Contains(strings.Join(got.signals, " "), "2 yanked") {
		t.Errorf("signals = %v, want yanked count", got.signals)
	}
}

func TestPEP503(t *testing.T) {
	cases := map[string]string{
		"Foo_Bar.Baz":          "foo-bar-baz",
		"eth_security_auditor": "eth-security-auditor",
		"a__b":                 "a-b",
	}
	for in, want := range cases {
		if got := pep503(in); got != want {
			t.Errorf("pep503(%q) = %q, want %q", in, want, got)
		}
	}
}

func TestNameMatches(t *testing.T) {
	if !nameMatches("PyPI", "eth_security_auditor", "eth-security-auditor") {
		t.Error("PyPI names should match under PEP 503")
	}
	if !nameMatches("npm", "Dev-Env", "dev-env") {
		t.Error("npm names should match case-insensitively")
	}
	if nameMatches("npm", "foo_bar", "foo-bar") {
		t.Error("npm must NOT collapse separators like PyPI")
	}
}

func TestFilterCandidates(t *testing.T) {
	all := []Candidate{{"npm", "a"}, {"PyPI", "b"}, {"crates.io", "c"}}
	if got := filterCandidates(all, ""); len(got) != 3 {
		t.Errorf("empty filter should return all, got %d", len(got))
	}
	if got := filterCandidates(all, "npm"); len(got) != 1 || got[0].Name != "a" {
		t.Errorf("npm filter = %v, want [{npm a}]", got)
	}
	if got := filterCandidates(all, "PYPI"); len(got) != 1 || got[0].Name != "b" {
		t.Errorf("case-insensitive filter failed: %v", got)
	}
}

func TestTrapdoorCandidateCount(t *testing.T) {
	// The Socket report lists 34 packages: 21 npm + 7 PyPI + 6 crates.io.
	var npm, pypi, crates int
	for _, c := range trapdoorCandidates {
		switch c.Ecosystem {
		case "npm":
			npm++
		case "PyPI":
			pypi++
		case "crates.io":
			crates++
		default:
			t.Errorf("unexpected ecosystem %q for %q", c.Ecosystem, c.Name)
		}
	}
	if npm != 21 || pypi != 7 || crates != 6 {
		t.Errorf("counts npm=%d pypi=%d crates=%d, want 21/7/6", npm, pypi, crates)
	}
	if len(trapdoorCandidates) != 34 {
		t.Errorf("total candidates = %d, want 34", len(trapdoorCandidates))
	}
}

func assertContains(t *testing.T, label string, got []string, want string) {
	t.Helper()
	for _, g := range got {
		if g == want {
			return
		}
	}
	t.Errorf("%s = %v, want to contain %q", label, got, want)
}
