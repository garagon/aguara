package intel

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// CurrentOSVAdmissionPolicy requires source evidence or reviewed exact tuples,
// rather than incidental words in vulnerability descriptions.
const CurrentOSVAdmissionPolicy = 1

//go:embed reviewed_osv.json
var reviewedOSVJSON []byte

type reviewedOSVKey struct{ id, ecosystem, name string }

var reviewedOSV = func() map[reviewedOSVKey]map[string]bool {
	var records []Record
	if err := json.Unmarshal(reviewedOSVJSON, &records); err != nil {
		panic("intel: invalid reviewed OSV compatibility data: " + err.Error())
	}
	out := make(map[reviewedOSVKey]map[string]bool, len(records))
	for _, r := range records {
		versions := make(map[string]bool, len(r.Versions))
		for _, v := range r.Versions {
			versions[v] = true
		}
		out[reviewedOSVKey{r.ID, r.Ecosystem, r.Name}] = versions
	}
	return out
}()

// ReviewedOSVVersions intersects incoming versions with explicitly reviewed
// advisory/package/version tuples. An ID alone never authorizes new coverage.
func ReviewedOSVVersions(id, ecosystem, name string, versions []string) []string {
	allowed := reviewedOSV[reviewedOSVKey{id, ecosystem, name}]
	var out []string
	for _, v := range versions {
		if allowed[v] {
			out = append(out, v)
		}
	}
	return out
}

// ApplyOSVAdmissionPolicy makes a generated or downloaded OSV snapshot safe to
// consume under the current classification policy. It does not authenticate
// the snapshot; callers must verify downloads first (or explicitly opt out).
// Do not use this on the separate, hand-curated manual snapshot.
//
// Legacy data lost its per-record admission evidence. Retain MAL namespace
// records, withdrawals, and only the reviewed exact tuples for other IDs.
// Unknown policy revisions receive the same conservative treatment. Source
// labels cannot exempt records from this migration, including mixed labels.
func ApplyOSVAdmissionPolicy(s Snapshot) Snapshot {
	if s.AdmissionPolicy == CurrentOSVAdmissionPolicy {
		return s
	}
	var records []Record
	for _, r := range s.Records {
		if r.Withdrawn || strings.HasPrefix(r.ID, "MAL-") {
			records = append(records, r)
			continue
		}
		r.Versions = ReviewedOSVVersions(r.ID, r.Ecosystem, r.Name, r.Versions)
		r.Ranges = nil
		if len(r.Versions) > 0 {
			records = append(records, r)
		}
	}
	// Legacy all-version data is almost entirely MAL namespace entries. Reuse
	// that immutable slice unless filtering is needed, avoiding a second copy.
	all := s.AllVersions
	for i, entry := range s.AllVersions {
		if strings.HasPrefix(entry.ID, "MAL-") {
			continue
		}
		all = make([]AllVersionsEntry, 0, len(s.AllVersions)-1)
		all = append(all, s.AllVersions[:i]...)
		for _, rest := range s.AllVersions[i+1:] {
			if strings.HasPrefix(rest.ID, "MAL-") {
				all = append(all, rest)
			}
		}
		break
	}
	s.Records = records
	s.AllVersions = all
	s.AdmissionPolicy = CurrentOSVAdmissionPolicy
	return s
}
