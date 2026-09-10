package osvimport_test

import (
	"encoding/json"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/osvimport"
	"github.com/stretchr/testify/require"
)

func TestImportRejectsIncidentalMalwareText(t *testing.T) {
	for _, text := range []string{
		"pip can load from a malicious package index",
		"This is not a malicious package",
		"An injection flaw allows credential exfiltration",
	} {
		t.Run(text, func(t *testing.T) {
			raw := mustMarshal(t, osvRecordFixture{
				ID: "GHSA-generic-cve", Details: text,
				Affected: []affectedFixture{{Package: packageFixture{Name: "pip", Ecosystem: "PyPI"}, Versions: []string{"25.1"}}},
			})
			snap, err := osvimport.Import([][]byte{raw}, osvimport.Options{})
			require.NoError(t, err)
			require.Empty(t, snap.Records)
			_, status := osvimport.ClassifyForEcosystem(raw, "PyPI")
			require.Equal(t, osvimport.StatusNeither, status)
		})
	}
}

func TestImportReviewedClassificationAndExactExceptions(t *testing.T) {
	tests := []struct {
		name, id, packageName, metadata string
		versions, want                  []string
	}{
		{"reviewed cwe", "GHSA-new-advisory", "new-package", `{"github_reviewed":true,"cwe_ids":["CWE-506"]}`, []string{"1.0.0"}, []string{"1.0.0"}},
		{"unreviewed cwe", "GHSA-new-advisory", "new-package", `{"github_reviewed":false,"cwe_ids":["CWE-506"]}`, []string{"1.0.0"}, nil},
		{"unrelated cwe", "GHSA-new-advisory", "new-package", `{"github_reviewed":true,"cwe_ids":["CWE-94"]}`, []string{"1.0.0"}, nil},
		{"cwe in value", "GHSA-new-advisory", "new-package", `{"github_reviewed":true,"notes":"CWE-506"}`, []string{"1.0.0"}, nil},
		{"wrong review type", "GHSA-new-advisory", "new-package", `{"github_reviewed":"true","cwe_ids":["CWE-506"]}`, []string{"1.0.0"}, nil},
		{"non github", "CVE-2026-1234", "new-package", `{"github_reviewed":true,"cwe_ids":["CWE-506"]}`, []string{"1.0.0"}, nil},
		{"historical exact", "GHSA-pjxp-f379-6284", "@fangrong/xoc", `{}`, []string{"1.0.5", "1.0.6", "9.0.0"}, []string{"1.0.6"}},
		{"historical wrong package", "GHSA-pjxp-f379-6284", "other", `{}`, []string{"1.0.6"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := mustMarshal(t, osvRecordFixture{ID: tt.id, DatabaseSpecific: json.RawMessage(tt.metadata), Affected: []affectedFixture{{Package: packageFixture{Name: tt.packageName, Ecosystem: "npm"}, Versions: tt.versions}}})
			snap, err := osvimport.Import([][]byte{raw}, osvimport.Options{})
			require.NoError(t, err)
			require.Equal(t, intel.CurrentOSVAdmissionPolicy, snap.AdmissionPolicy)
			rec, status := osvimport.ClassifyForEcosystem(raw, "npm")
			if len(tt.want) == 0 {
				require.Empty(t, snap.Records)
				require.Equal(t, osvimport.StatusNeither, status)
				return
			}
			require.Len(t, snap.Records, 1)
			require.Equal(t, tt.want, snap.Records[0].Versions)
			require.Equal(t, osvimport.StatusKept, status)
			require.Equal(t, rec, snap.Records[0])
		})
	}
}

func TestImportRejectsImpostorOriginMetadata(t *testing.T) {
	for _, value := range []string{
		`{"note":"malicious-packages-origins"}`,
		`{"nested":{"malicious-packages-origins":[{"source":"ossf"}]}}`,
		`{"malicious-packages-origins":"yes"}`,
		`{"malicious-packages-origins":[]}`,
		`{"malicious-packages-origins":[{}]}`,
	} {
		t.Run(value, func(t *testing.T) {
			raw := mustMarshal(t, osvRecordFixture{
				ID: "GHSA-metadata-impostor", DatabaseSpecific: json.RawMessage(value),
				Affected: []affectedFixture{{Package: packageFixture{Name: "normal", Ecosystem: "npm"}, Versions: []string{"1.0.0"}}},
			})
			snap, err := osvimport.Import([][]byte{raw}, osvimport.Options{})
			require.NoError(t, err)
			require.Empty(t, snap.Records)
		})
	}
}

func TestImportRejectsContradictedPYSECGuardrailsVersions(t *testing.T) {
	// The PYSEC list includes 0.10.0 despite its own text identifying it as
	// unaffected. The GHSA counterpart lists only the malicious 0.10.1 release.
	raw := mustMarshal(t, osvRecordFixture{
		ID: "PYSEC-2026-206", Details: "Malicious version 0.10.1; 0.10.0 is unaffected.",
		Affected: []affectedFixture{{Package: packageFixture{Name: "guardrails-ai", Ecosystem: "PyPI"}, Versions: []string{"0.1.0", "0.10.0"}}},
	})
	snap, err := osvimport.Import([][]byte{raw}, osvimport.Options{})
	require.NoError(t, err)
	require.Empty(t, snap.Records)
	_, status := osvimport.ClassifyForEcosystem(raw, "PyPI")
	require.Equal(t, osvimport.StatusNeither, status)
}
