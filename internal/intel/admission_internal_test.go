package intel

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestReviewedOSVDataIntegrity(t *testing.T) {
	var rows []struct {
		ID        string   `json:"id"`
		Ecosystem string   `json:"ecosystem"`
		Name      string   `json:"name"`
		Versions  []string `json:"versions"`
		Source    string   `json:"source"`
		SHA       string   `json:"source_sha256"`
	}
	if err := json.Unmarshal(reviewedOSVJSON, &rows); err != nil {
		t.Fatal(err)
	}
	seen := map[reviewedOSVKey]bool{}
	for _, r := range rows {
		key := reviewedOSVKey{r.ID, r.Ecosystem, r.Name}
		if seen[key] || r.ID == "" || r.Name == "" || CanonicaliseEcosystem(r.Ecosystem) != r.Ecosystem || len(r.Versions) == 0 {
			t.Fatalf("invalid or duplicate compatibility entry: %+v", r)
		}
		seen[key] = true
		if r.Source != "https://api.osv.dev/v1/vulns/"+r.ID {
			t.Fatalf("missing source: %s", r.ID)
		}
		hash, err := hex.DecodeString(r.SHA)
		if err != nil || len(hash) != 32 {
			t.Fatalf("invalid evidence digest: %s", r.ID)
		}
		versions := map[string]bool{}
		for _, v := range r.Versions {
			if v == "" || versions[v] {
				t.Fatalf("invalid version for %s", r.ID)
			}
			versions[v] = true
		}
	}
}
