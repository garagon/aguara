package main

import (
	"encoding/json"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// classifyStatus enumerates the exact filter funnel
// osvimport.convertOSVRecord walks: ecosystem-miss -> withdrawn ->
// ranges-only -> signal-or-keyword pass -> kept. Each record lands
// in exactly one bucket so the per-ecosystem totals add up.
type classifyStatus int

const (
	statusEcosystemMiss classifyStatus = iota
	statusWithdrawn
	statusRangesOnly
	statusNeither
	statusKeptSignal
	statusKeptKeyword
)

// classifyRecord parses one OSV JSON record and returns the
// produced intel.Record plus the status bucket. The logic mirrors
// osvimport.convertOSVRecord exactly with one intentional
// difference: ecosystem matching is case-sensitive against the raw
// OSV string (e.g. "Go", "crates.io"), not against
// osvimport.canonicaliseEcosystem which today rejects everything
// except npm / pypi. Once PR #1 widens the canonicaliser, this
// mirror can be deleted in favour of a direct osvimport call.
//
// SYNC TARGET: internal/intel/osvimport/osvimport.go::convertOSVRecord
// Any change to the production filter must be mirrored here, or the
// measurement numbers diverge from what the importer will actually
// produce.
func classifyRecord(raw []byte, targetEcosystem string) (intel.Record, classifyStatus) {
	var osv osvJSON
	if err := json.Unmarshal(raw, &osv); err != nil {
		return intel.Record{}, statusEcosystemMiss
	}
	if osv.ID == "" || len(osv.Affected) == 0 {
		return intel.Record{}, statusEcosystemMiss
	}

	// Find the FIRST affected[] entry that targets the ecosystem of
	// interest. OSV records can list multiple ecosystems
	// (e.g. a GHSA aliased across npm + RubyGems); we treat each
	// (record, ecosystem) pair independently, mirroring
	// convertOSVRecord's loop body.
	var aff *osvAffectedJSON
	for i := range osv.Affected {
		if osv.Affected[i].Package.Ecosystem == targetEcosystem {
			aff = &osv.Affected[i]
			break
		}
	}
	if aff == nil {
		return intel.Record{}, statusEcosystemMiss
	}

	withdrawn := osv.Withdrawn != ""
	if withdrawn {
		// Withdrawn passes through as a tombstone, NOT a kept
		// record. The renderer / merge layer would emit it so the
		// runtime matcher can retract a previously-live copy.
		return intel.Record{}, statusWithdrawn
	}

	if len(aff.Versions) == 0 {
		return intel.Record{}, statusRangesOnly
	}

	signal := hasSignal(&osv)
	keyword := hasKeyword(&osv)
	if !signal && !keyword {
		return intel.Record{}, statusNeither
	}

	rec := intel.Record{
		ID:        osv.ID,
		Aliases:   append([]string(nil), osv.Aliases...),
		Ecosystem: targetEcosystem,
		Name:      aff.Package.Name,
		Kind:      intel.KindMalicious,
		Summary:   pickSummary(&osv),
		Versions:  append([]string(nil), aff.Versions...),
	}
	for _, ref := range osv.References {
		if ref.URL != "" {
			rec.References = append(rec.References, ref.URL)
		}
	}

	if signal {
		return rec, statusKeptSignal
	}
	return rec, statusKeptKeyword
}

// osvJSON mirrors osvimport's private osvRecord. We keep it private
// here too because PR #1 will widen the importer and this file can
// then call into osvimport directly.
type osvJSON struct {
	ID               string             `json:"id"`
	Aliases          []string           `json:"aliases,omitempty"`
	Withdrawn        string             `json:"withdrawn,omitempty"`
	Summary          string             `json:"summary,omitempty"`
	Details          string             `json:"details,omitempty"`
	Affected         []osvAffectedJSON  `json:"affected,omitempty"`
	References       []osvReferenceJSON `json:"references,omitempty"`
	DatabaseSpecific json.RawMessage    `json:"database_specific,omitempty"`
}

type osvAffectedJSON struct {
	Package  osvPackageJSON `json:"package"`
	Versions []string       `json:"versions,omitempty"`
}

type osvPackageJSON struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvReferenceJSON struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// highConfidenceKeywords mirrors osvimport.highConfidenceKeywords.
// SYNC TARGET: internal/intel/osvimport/osvimport.go.
var highConfidenceKeywords = []string{
	"malicious package",
	"malicious npm package",
	"malicious python package",
	"compromised package",
	"credential stealing",
	"credential exfiltration",
	"typosquat malware",
	"install script malware",
}

func hasSignal(osv *osvJSON) bool {
	if strings.HasPrefix(osv.ID, "MAL-") {
		return true
	}
	// OpenSSF Malicious Packages records embed an
	// `malicious-packages-origins` key inside database_specific.
	// A substring check on the raw JSON is good enough here; the
	// importer does the same.
	if len(osv.DatabaseSpecific) > 0 && strings.Contains(string(osv.DatabaseSpecific), "malicious-packages-origins") {
		return true
	}
	return false
}

func hasKeyword(osv *osvJSON) bool {
	hay := strings.ToLower(osv.Summary + " " + osv.Details)
	for _, kw := range highConfidenceKeywords {
		if strings.Contains(hay, kw) {
			return true
		}
	}
	return false
}

func pickSummary(osv *osvJSON) string {
	if osv.Summary != "" {
		return osv.Summary
	}
	if osv.Details != "" {
		// One-line preview only; the renderer cares about source
		// bytes, so a long Details would inflate the size estimate.
		if i := strings.IndexAny(osv.Details, "\r\n"); i > 0 {
			return osv.Details[:i]
		}
		return osv.Details
	}
	return ""
}
