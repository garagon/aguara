// Command verify-trapdoor-intel checks the public OSV feed and the
// npm / PyPI / crates.io registries for the package surface of the
// TrapDoor crypto-stealer supply-chain campaign (Socket Research,
// 2026-05-24) and reports, per package, whether an exact malicious
// version is confirmed and therefore safe to encode as a manual
// intel entry.
//
// Why this exists. The TrapDoor hotfix (a follow-up PR) adds
// hand-curated CompromisedPackage records so `aguara check` can
// block confirmed malicious package/version tuples even when the
// embedded OSV snapshot lags or only carries version ranges. The
// project rule is "no speculative versions": a manual intel entry
// must cite an exact version that OSV or a registry actually
// confirms. Package names alone are not enough. This tool produces
// the evidence the maintainer reviews before any tuple is added.
//
// The incident feed is volatile -- OSV can publish, widen, or
// withdraw records within hours during an active campaign. Run this
// tool on the day the hotfix is prepared; do not trust numbers from
// a previous run.
//
// Network. The tool makes live HTTPS GET/POST requests to:
//
//	https://api.osv.dev/v1/query           (POST, package query)
//	https://registry.npmjs.org/<name>      (GET)
//	https://pypi.org/pypi/<name>/json       (GET)
//	https://crates.io/api/v1/crates/<name>  (GET)
//
// It is dev-only: not shipped in any distribution channel, not
// invoked by `make build`. It IS compiled by `go test ./...` and
// `go vet ./...`, so the parsing, URL-escaping, and classification
// logic carry unit tests that use static JSON and never touch the
// network.
//
// Usage:
//
//	# Verify all 34 candidates, emit JSON to stdout
//	go run ./tools/verify-trapdoor-intel
//
//	# Limit to one ecosystem and write a human-readable summary
//	go run ./tools/verify-trapdoor-intel --ecosystem npm --format md
//
//	# Write the JSON report to a file for review / PR body
//	go run ./tools/verify-trapdoor-intel --out trapdoor-verify.json
//
// Classification. A candidate is reported manual_intel_ready=true
// only when OSV carries exact affected versions, or when OSV carries
// ranges only AND the registry independently confirms a security
// removal (in which case a human still pins the exact versions). A
// ranges-only OSV record with no registry confirmation is held: the
// range matcher work, not manual exact-version intel, is the right
// path for it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	osvQueryURL = "https://api.osv.dev/v1/query"
	userAgent   = "aguara-verify-trapdoor-intel/dev (+https://github.com/garagon/aguara)"
)

// Candidate is one package to verify. Ecosystem holds the OSV bucket
// string byte-for-byte ("npm", "PyPI", "crates.io"); the OSV query
// API and the registry URL builders both depend on that exact form.
type Candidate struct {
	Ecosystem string
	Name      string
}

// trapdoorCandidates is the package surface from the Socket TrapDoor
// report (2026-05-24): 21 npm + 7 PyPI + 6 crates.io = 34 packages.
// The list is the campaign's published names only; this tool exists
// precisely because the affected versions still need confirming.
var trapdoorCandidates = []Candidate{
	{"npm", "async-pipeline-builder"},
	{"npm", "build-scripts-utils"},
	{"npm", "chain-key-validator"},
	{"npm", "crypto-credential-scanner"},
	{"npm", "defi-env-auditor"},
	{"npm", "defi-threat-scanner"},
	{"npm", "deployment-key-auditor"},
	{"npm", "dev-env-bootstrapper"},
	{"npm", "eth-wallet-sentinel"},
	{"npm", "llm-context-compressor"},
	{"npm", "mnemonic-safety-check"},
	{"npm", "model-switch-router"},
	{"npm", "node-setup-helpers"},
	{"npm", "project-init-tools"},
	{"npm", "prompt-engineering-toolkit"},
	{"npm", "solidity-deploy-guard"},
	{"npm", "token-usage-tracker"},
	{"npm", "wallet-backup-verifier"},
	{"npm", "wallet-security-checker"},
	{"npm", "web3-secrets-detector"},
	{"npm", "workspace-config-loader"},
	{"PyPI", "cryptowallet-safety"},
	{"PyPI", "data-pipeline-check"},
	{"PyPI", "defi-risk-scanner"},
	{"PyPI", "env-loader-cli"},
	{"PyPI", "eth-security-auditor"},
	{"PyPI", "git-config-sync"},
	{"PyPI", "solidity-build-guard"},
	{"crates.io", "move-analyzer-build"},
	{"crates.io", "move-compiler-tools"},
	{"crates.io", "move-project-builder"},
	{"crates.io", "sui-framework-helpers"},
	{"crates.io", "sui-move-build-helper"},
	{"crates.io", "sui-sdk-build-utils"},
}

// knownIOCMarkers are the high-signal, campaign-specific strings from
// the Socket report. The tool scans each package's raw OSV record
// text for them; a hit is corroboration that the OSV record really is
// this campaign and not a name collision with an unrelated advisory.
// The list stays distinctive on purpose -- generic paths like
// ".cursorrules" or "CLAUDE.md" are not included because they would
// match unrelated records.
var knownIOCMarkers = []string{
	"ddjidd564.github.io",
	"defi-security-best-practices",
	"trap-core.js",
	"p-2024-001",
	"cargo-build-helper-2026",
}

// Report is the top-level JSON document the tool emits.
type Report struct {
	GeneratedAt string            `json:"generated_at"`
	Source      string            `json:"source"`
	Candidates  []CandidateReport `json:"candidates"`
}

// CandidateReport is one package's verification verdict.
type CandidateReport struct {
	Ecosystem        string     `json:"ecosystem"`
	Name             string     `json:"name"`
	OSVIDs           []string   `json:"osv_ids"`
	ExactVersions    []string   `json:"exact_versions"`
	Ranges           []RangeOut `json:"ranges"`
	Aliases          []string   `json:"aliases,omitempty"`
	IOCMarkersFound  []string   `json:"ioc_markers_found,omitempty"`
	RegistrySignals  []string   `json:"registry_signals"`
	SourceURLs       []string   `json:"source_urls"`
	Disposition      string     `json:"disposition"`
	ManualIntelReady bool       `json:"manual_intel_ready"`
	Notes            string     `json:"notes"`
	Errors           []string   `json:"errors,omitempty"`
}

// Disposition values tell the maintainer which mechanism covers a
// package, because "confirmed malicious" and "addable as exact-version
// manual intel" are not the same thing.
const (
	// dispReadyExact: OSV (or a registry) supplies exact malicious
	// versions, so the package can be encoded as a manual intel tuple
	// right now. Only this disposition sets ManualIntelReady=true.
	dispReadyExact = "ready_exact"
	// dispRangesConfirmed: the package is confirmed malicious (a
	// registry security removal corroborates the OSV record) but the
	// only version data is a range -- typically introduced:0 with the
	// original versions wiped from the registry. There is nothing
	// exact to pin. This is the range matcher's job, NOT manual
	// exact-version intel. Encoding a tuple here would either invent a
	// version (forbidden) or omit it (invalid).
	dispRangesConfirmed = "ranges_only_confirmed"
	// dispRangesUnconfirmed: OSV carries ranges only and no registry
	// confirmation. Verify before treating as malicious at all.
	dispRangesUnconfirmed = "ranges_only_unconfirmed"
	// dispHold: no exact versions, no ranges, no confirmation. Not
	// actionable yet; re-check the feed.
	dispHold = "hold"
)

// RangeOut is a flattened OSV affected-range, one per OSV range entry.
type RangeOut struct {
	Type         string `json:"type,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// --- OSV /v1/query wire types -------------------------------------

type osvQueryRequest struct {
	Package osvQueryPackage `json:"package"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Withdrawn  string         `json:"withdrawn"`
	Affected   []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvReference struct {
	URL string `json:"url"`
}

// osvSignals is the parsed, deduped distillate of an OSV query
// response for a single candidate.
type osvSignals struct {
	ids           []string
	exactVersions []string
	ranges        []RangeOut
	aliases       []string
	withdrawn     []string
	iocMarkers    []string
}

// parseOSVQueryResponse decodes an OSV /v1/query response body and
// extracts the signals for the queried ecosystem/name. It is pure:
// no network, no globals. Affected entries are filtered to the
// queried package so a vuln that covers several packages contributes
// only its relevant versions/ranges.
func parseOSVQueryResponse(body []byte, ecosystem, name string) (osvSignals, error) {
	var resp osvQueryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return osvSignals{}, fmt.Errorf("decode OSV response: %w", err)
	}

	ids := newStringSet()
	versions := newStringSet()
	aliases := newStringSet()
	withdrawn := newStringSet()
	var ranges []RangeOut

	for _, v := range resp.Vulns {
		if v.ID != "" {
			ids.add(v.ID)
		}
		// A withdrawn advisory has been retracted by OSV. Record that it
		// exists so the report still surfaces it, but do NOT let its
		// versions or ranges feed the readiness verdict: confirming
		// manual intel from a retracted advisory would defeat the whole
		// point of the tool.
		if v.Withdrawn != "" {
			if v.ID != "" {
				withdrawn.add(v.ID)
			}
			continue
		}
		for _, a := range v.Aliases {
			aliases.add(a)
		}
		for _, aff := range v.Affected {
			if !strings.EqualFold(aff.Package.Ecosystem, ecosystem) ||
				!nameMatches(ecosystem, aff.Package.Name, name) {
				continue
			}
			for _, ver := range aff.Versions {
				versions.add(ver)
			}
			for _, r := range aff.Ranges {
				if out, ok := flattenRange(r); ok {
					ranges = append(ranges, out)
				}
			}
		}
	}

	// Marker scan over the whole response: the body belongs to this
	// candidate, so any campaign marker present is attributable to it.
	lower := strings.ToLower(string(body))
	var markers []string
	for _, m := range knownIOCMarkers {
		if strings.Contains(lower, m) {
			markers = append(markers, m)
		}
	}

	return osvSignals{
		ids:           ids.sorted(),
		exactVersions: versions.sorted(),
		ranges:        ranges,
		aliases:       aliases.sorted(),
		withdrawn:     withdrawn.sorted(),
		iocMarkers:    markers,
	}, nil
}

// flattenRange collapses one OSV range's events into a single
// RangeOut. Returns ok=false for an empty range. SEMVER and ECOSYSTEM
// ranges both carry introduced/fixed/last_affected events; we surface
// the first of each because malicious-package records do not use
// multi-segment ranges in practice.
func flattenRange(r osvRange) (RangeOut, bool) {
	out := RangeOut{Type: r.Type}
	any := false
	for _, e := range r.Events {
		if e.Introduced != "" && out.Introduced == "" {
			out.Introduced = e.Introduced
			any = true
		}
		if e.Fixed != "" && out.Fixed == "" {
			out.Fixed = e.Fixed
			any = true
		}
		if e.LastAffected != "" && out.LastAffected == "" {
			out.LastAffected = e.LastAffected
			any = true
		}
	}
	return out, any
}

// --- registry probing ---------------------------------------------

// registrySignals is the parsed result of a registry metadata query.
type registrySignals struct {
	found             bool
	signals           []string
	confirmsMalicious bool
}

// npmRegistryURL builds the npm registry metadata URL, escaping the
// slash in a scoped name so "@scope/pkg" becomes "@scope%2fpkg".
// npm treats the scope separator as the only character needing
// escaping; the "@" is left intact.
func npmRegistryURL(name string) string {
	return "https://registry.npmjs.org/" + strings.ReplaceAll(name, "/", "%2f")
}

func pypiRegistryURL(name string) string {
	return "https://pypi.org/pypi/" + name + "/json"
}

func cratesRegistryURL(name string) string {
	return "https://crates.io/api/v1/crates/" + name
}

// registryURLFor returns the registry metadata URL for a candidate,
// or "" when the ecosystem has no registry probe.
func registryURLFor(eco, name string) string {
	switch {
	case strings.EqualFold(eco, "npm"):
		return npmRegistryURL(name)
	case strings.EqualFold(eco, "PyPI"):
		return pypiRegistryURL(name)
	case strings.EqualFold(eco, "crates.io"):
		return cratesRegistryURL(name)
	default:
		return ""
	}
}

type npmRegistry struct {
	Description string `json:"description"`
	Versions    map[string]struct {
		Deprecated string `json:"deprecated"`
	} `json:"versions"`
}

// parseNPMRegistry reports the security signals in an npm registry
// document. npm replaces a package taken down for malware with a
// "security holding package" placeholder; that description is a
// strong malicious-removal confirmation.
func parseNPMRegistry(body []byte) (registrySignals, error) {
	var reg npmRegistry
	if err := json.Unmarshal(body, &reg); err != nil {
		return registrySignals{}, fmt.Errorf("decode npm registry: %w", err)
	}
	out := registrySignals{found: true}
	out.signals = append(out.signals, fmt.Sprintf("%d published version(s)", len(reg.Versions)))
	if strings.Contains(strings.ToLower(reg.Description), "security holding package") {
		out.signals = append(out.signals, "npm security holding package (taken down)")
		out.confirmsMalicious = true
	}
	deprecated := 0
	for _, v := range reg.Versions {
		if v.Deprecated != "" {
			deprecated++
		}
	}
	if deprecated > 0 {
		out.signals = append(out.signals, fmt.Sprintf("%d deprecated version(s)", deprecated))
	}
	return out, nil
}

type pypiRegistry struct {
	Releases        map[string]json.RawMessage `json:"releases"`
	Vulnerabilities []struct {
		ID string `json:"id"`
	} `json:"vulnerabilities"`
}

// parsePyPIRegistry reports security signals in a PyPI JSON document.
// PyPI surfaces an OSV-backed "vulnerabilities" array; a non-empty
// one is a malicious/known-vulnerable confirmation.
func parsePyPIRegistry(body []byte) (registrySignals, error) {
	var reg pypiRegistry
	if err := json.Unmarshal(body, &reg); err != nil {
		return registrySignals{}, fmt.Errorf("decode PyPI registry: %w", err)
	}
	out := registrySignals{found: true}
	out.signals = append(out.signals, fmt.Sprintf("%d release(s)", len(reg.Releases)))
	if len(reg.Vulnerabilities) > 0 {
		out.signals = append(out.signals, fmt.Sprintf("%d PyPI vulnerability advisory(ies)", len(reg.Vulnerabilities)))
		out.confirmsMalicious = true
	}
	return out, nil
}

type cratesRegistry struct {
	Versions []struct {
		Num    string `json:"num"`
		Yanked bool   `json:"yanked"`
	} `json:"versions"`
}

// parseCratesRegistry reports signals in a crates.io document. A
// yanked crate is noted but NOT treated as a malicious confirmation:
// crates are yanked for many non-security reasons, so the human must
// decide. This keeps crates.io conservative, matching the spec's
// guidance to hold crates manual intel until versions are verified.
func parseCratesRegistry(body []byte) (registrySignals, error) {
	var reg cratesRegistry
	if err := json.Unmarshal(body, &reg); err != nil {
		return registrySignals{}, fmt.Errorf("decode crates.io registry: %w", err)
	}
	out := registrySignals{found: true}
	yanked := 0
	for _, v := range reg.Versions {
		if v.Yanked {
			yanked++
		}
	}
	out.signals = append(out.signals, fmt.Sprintf("%d version(s), %d yanked", len(reg.Versions), yanked))
	return out, nil
}

// parseRegistry dispatches to the per-ecosystem registry parser.
func parseRegistry(eco string, body []byte) (registrySignals, error) {
	switch {
	case strings.EqualFold(eco, "npm"):
		return parseNPMRegistry(body)
	case strings.EqualFold(eco, "PyPI"):
		return parsePyPIRegistry(body)
	case strings.EqualFold(eco, "crates.io"):
		return parseCratesRegistry(body)
	default:
		return registrySignals{}, fmt.Errorf("no registry parser for ecosystem %q", eco)
	}
}

// --- classification -----------------------------------------------

// classify is the conservative verdict function. It never invents a
// version. ManualIntelReady (the bool) is true ONLY for an exact-
// version disposition; "confirmed malicious" with range-only data is
// reported as such but NOT as exact-version-ready, per the spec's
// guidance that range-only-without-exact-versions packages do not get
// manual intel until exact bad versions are confirmed.
func classify(hasExact, hasRanges, hasOSV, registryConfirms bool) (disposition string, ready bool, notes string) {
	switch {
	case hasExact:
		if hasRanges {
			return dispReadyExact, true, "OSV carries exact version(s); ranges also present, but the exact versions are enough for manual hotfix intel"
		}
		return dispReadyExact, true, "OSV carries exact version(s); ready for manual exact-version intel"
	case hasRanges && registryConfirms:
		return dispRangesConfirmed, false, "confirmed malicious (registry security removal corroborates OSV), but OSV carries ranges only (e.g. introduced:0) and no exact versions are recoverable; this is range-matcher work, do NOT add exact-version manual intel"
	case hasRanges:
		return dispRangesUnconfirmed, false, "OSV carries ranges only (no exact versions) and the registry does not confirm; verify before any intel -- wait for OSV exact versions or use the range matcher"
	case hasOSV:
		return dispHold, false, "OSV record present but it carries no exact versions or ranges for this package; hold for human review"
	case registryConfirms:
		return dispHold, false, "no OSV record yet, but the registry shows a security signal; hold and re-check OSV"
	default:
		return dispHold, false, "no OSV record and no registry security confirmation; hold"
	}
}

// --- HTTP layer (not exercised by unit tests) ---------------------

func queryOSV(ctx context.Context, client *http.Client, eco, name string) ([]byte, error) {
	payload, err := json.Marshal(osvQueryRequest{Package: osvQueryPackage{Name: name, Ecosystem: eco}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return doRequest(client, req)
}

func queryRegistry(ctx context.Context, client *http.Client, url string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil // package not on the registry: a fact, not an error
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

func doRequest(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// verifyCandidate runs the live OSV + registry lookups for one
// candidate and returns its filled report row. Lookup failures are
// recorded in the row's Errors and do not abort the run.
func verifyCandidate(ctx context.Context, client *http.Client, c Candidate) CandidateReport {
	row := CandidateReport{
		Ecosystem:       c.Ecosystem,
		Name:            c.Name,
		OSVIDs:          []string{},
		ExactVersions:   []string{},
		Ranges:          []RangeOut{},
		RegistrySignals: []string{},
		SourceURLs:      []string{},
	}

	var sig osvSignals
	if body, err := queryOSV(ctx, client, c.Ecosystem, c.Name); err != nil {
		row.Errors = append(row.Errors, "osv query: "+err.Error())
	} else if parsed, perr := parseOSVQueryResponse(body, c.Ecosystem, c.Name); perr != nil {
		row.Errors = append(row.Errors, "osv parse: "+perr.Error())
	} else {
		sig = parsed
		row.OSVIDs = parsed.ids
		row.ExactVersions = parsed.exactVersions
		row.Ranges = parsed.ranges
		row.Aliases = parsed.aliases
		row.IOCMarkersFound = parsed.iocMarkers
		for _, id := range parsed.ids {
			row.SourceURLs = append(row.SourceURLs, "https://osv.dev/vulnerability/"+id)
		}
		for _, id := range parsed.withdrawn {
			row.RegistrySignals = append(row.RegistrySignals, "OSV "+id+" is WITHDRAWN")
		}
	}

	var reg registrySignals
	if url := registryURLFor(c.Ecosystem, c.Name); url != "" {
		row.SourceURLs = append(row.SourceURLs, url)
		body, found, err := queryRegistry(ctx, client, url)
		switch {
		case err != nil:
			row.Errors = append(row.Errors, "registry query: "+err.Error())
		case !found:
			row.RegistrySignals = append(row.RegistrySignals, "not present on registry (404)")
		default:
			if parsed, perr := parseRegistry(c.Ecosystem, body); perr != nil {
				row.Errors = append(row.Errors, "registry parse: "+perr.Error())
			} else {
				reg = parsed
				row.RegistrySignals = append(row.RegistrySignals, parsed.signals...)
			}
		}
	}

	row.Disposition, row.ManualIntelReady, row.Notes = classify(
		len(sig.exactVersions) > 0,
		len(sig.ranges) > 0,
		len(sig.ids) > 0,
		reg.confirmsMalicious,
	)
	return row
}

// --- string-set helper --------------------------------------------

type stringSet struct {
	m map[string]struct{}
}

func newStringSet() *stringSet { return &stringSet{m: map[string]struct{}{}} }

func (s *stringSet) add(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	s.m[v] = struct{}{}
}

func (s *stringSet) sorted() []string {
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nameMatches compares two package names under the ecosystem's
// matching rule. PyPI is PEP 503-insensitive; everything else is
// compared case-insensitively.
func nameMatches(eco, a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	if strings.EqualFold(eco, "PyPI") {
		return pep503(a) == pep503(b)
	}
	return false
}

// pep503 lower-cases and collapses runs of -, _, . into a single -.
func pep503(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevSep := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// --- output --------------------------------------------------------

func renderMarkdown(rep Report) string {
	var b strings.Builder
	counts := map[string]int{}
	for _, c := range rep.Candidates {
		counts[c.Disposition]++
	}
	fmt.Fprintf(&b, "# TrapDoor intel verification\n\n")
	fmt.Fprintf(&b, "Generated %s. Source: %s\n\n", rep.GeneratedAt, rep.Source)
	fmt.Fprintf(&b, "%d candidates total: %d ready_exact, %d ranges_only_confirmed, %d ranges_only_unconfirmed, %d hold.\n\n",
		len(rep.Candidates), counts[dispReadyExact], counts[dispRangesConfirmed], counts[dispRangesUnconfirmed], counts[dispHold])
	fmt.Fprintf(&b, "Only `ready_exact` packages are safe to encode as manual exact-version intel.\n\n")
	fmt.Fprintf(&b, "| Ecosystem | Package | OSV IDs | Exact versions | Ranges | IOC markers | Disposition |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|\n")
	for _, c := range rep.Candidates {
		ranges := make([]string, 0, len(c.Ranges))
		for _, r := range c.Ranges {
			ranges = append(ranges, summariseRange(r))
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			c.Ecosystem, c.Name,
			joinOrDash(c.OSVIDs), joinOrDash(c.ExactVersions),
			joinOrDash(ranges), joinOrDash(c.IOCMarkersFound), c.Disposition)
	}
	return b.String()
}

func summariseRange(r RangeOut) string {
	parts := make([]string, 0, 3)
	if r.Introduced != "" {
		parts = append(parts, "introduced "+r.Introduced)
	}
	if r.Fixed != "" {
		parts = append(parts, "fixed "+r.Fixed)
	}
	if r.LastAffected != "" {
		parts = append(parts, "last_affected "+r.LastAffected)
	}
	return strings.Join(parts, ", ")
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, "; ")
}

// --- main ----------------------------------------------------------

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "verify-trapdoor-intel:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify-trapdoor-intel", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: json or md")
	ecoFilter := fs.String("ecosystem", "", "limit to one ecosystem (npm, PyPI, crates.io); empty = all")
	out := fs.String("out", "", "write report to this file instead of stdout")
	timeout := fs.Duration("timeout", 20*time.Second, "per-request HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "json" && *format != "md" {
		return fmt.Errorf("unknown --format %q (want json or md)", *format)
	}

	candidates := filterCandidates(trapdoorCandidates, *ecoFilter)
	if len(candidates) == 0 {
		return fmt.Errorf("no candidates match --ecosystem %q", *ecoFilter)
	}

	client := &http.Client{Timeout: *timeout}
	rep := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates",
		Candidates:  make([]CandidateReport, 0, len(candidates)),
	}
	for _, c := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
		row := verifyCandidate(ctx, client, c)
		cancel()
		rep.Candidates = append(rep.Candidates, row)
		fmt.Fprintf(os.Stderr, "checked %s/%s: osv=%d exact=%d ranges=%d ready=%v\n",
			c.Ecosystem, c.Name, len(row.OSVIDs), len(row.ExactVersions), len(row.Ranges), row.ManualIntelReady)
	}

	var rendered []byte
	if *format == "md" {
		rendered = []byte(renderMarkdown(rep))
	} else {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		rendered = append(b, '\n')
	}

	if *out != "" {
		return os.WriteFile(*out, rendered, 0o644)
	}
	_, err := stdout.Write(rendered)
	return err
}

func filterCandidates(all []Candidate, ecoFilter string) []Candidate {
	if strings.TrimSpace(ecoFilter) == "" {
		return all
	}
	var out []Candidate
	for _, c := range all {
		if strings.EqualFold(c.Ecosystem, ecoFilter) {
			out = append(out, c)
		}
	}
	return out
}
