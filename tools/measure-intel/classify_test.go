package main

import (
	"encoding/json"
	"testing"
)

func mkRaw(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestClassifyRecord_KeptViaMALSignal(t *testing.T) {
	raw := mkRaw(t, map[string]any{
		"id": "MAL-2024-0001",
		"affected": []any{map[string]any{
			"package":  map[string]any{"name": "evil-crate", "ecosystem": "crates.io"},
			"versions": []string{"1.2.3"},
		}},
	})
	rec, status := classifyRecord(raw, "crates.io")
	if status != statusKeptSignal {
		t.Fatalf("status = %v, want statusKeptSignal", status)
	}
	if rec.Name != "evil-crate" || rec.Ecosystem != "crates.io" {
		t.Errorf("record: %+v", rec)
	}
}

func TestClassifyRecord_KeptViaKeyword(t *testing.T) {
	raw := mkRaw(t, map[string]any{
		"id":      "GHSA-xxxx-yyyy-zzzz",
		"summary": "Malicious package distributing credential stealing payload",
		"affected": []any{map[string]any{
			"package":  map[string]any{"name": "rogue-gem", "ecosystem": "RubyGems"},
			"versions": []string{"0.0.1"},
		}},
	})
	_, status := classifyRecord(raw, "RubyGems")
	if status != statusKeptKeyword {
		t.Fatalf("status = %v, want statusKeptKeyword", status)
	}
}

func TestClassifyRecord_DropsRangesOnly(t *testing.T) {
	// MAL- signal would normally pass but ranges-only is the hard
	// drop because the matcher cannot consume ranges.
	raw := mkRaw(t, map[string]any{
		"id": "MAL-2024-9999",
		"affected": []any{map[string]any{
			"package": map[string]any{"name": "ranged-pkg", "ecosystem": "Go"},
		}},
	})
	_, status := classifyRecord(raw, "Go")
	if status != statusRangesOnly {
		t.Fatalf("status = %v, want statusRangesOnly", status)
	}
}

func TestClassifyRecord_DropsNeitherSignalNorKeyword(t *testing.T) {
	// Plain CVE record with exact versions, no MAL- prefix, no
	// keyword hit. This is the path that keeps Aguara out of
	// general-CVE territory.
	raw := mkRaw(t, map[string]any{
		"id":      "CVE-2024-1111",
		"summary": "Vulnerability in the parser allows remote code execution",
		"affected": []any{map[string]any{
			"package":  map[string]any{"name": "innocent-pkg", "ecosystem": "Maven"},
			"versions": []string{"1.0.0"},
		}},
	})
	_, status := classifyRecord(raw, "Maven")
	if status != statusNeither {
		t.Fatalf("status = %v, want statusNeither", status)
	}
}

func TestClassifyRecord_WithdrawnPassesAsTombstone(t *testing.T) {
	raw := mkRaw(t, map[string]any{
		"id":        "MAL-2024-2222",
		"withdrawn": "2024-01-15T00:00:00Z",
		"affected": []any{map[string]any{
			"package":  map[string]any{"name": "retracted", "ecosystem": "Packagist"},
			"versions": []string{"1.0.0"},
		}},
	})
	_, status := classifyRecord(raw, "Packagist")
	if status != statusWithdrawn {
		t.Fatalf("status = %v, want statusWithdrawn", status)
	}
}

func TestClassifyRecord_EcosystemMissDoesNotMatch(t *testing.T) {
	raw := mkRaw(t, map[string]any{
		"id": "MAL-2024-3333",
		"affected": []any{map[string]any{
			"package":  map[string]any{"name": "wrong-eco", "ecosystem": "npm"},
			"versions": []string{"1.0.0"},
		}},
	})
	// Asking for crates.io but the record affects npm.
	_, status := classifyRecord(raw, "crates.io")
	if status != statusEcosystemMiss {
		t.Fatalf("status = %v, want statusEcosystemMiss", status)
	}
}

func TestClassifyRecord_OpenSSFOriginsCountAsSignal(t *testing.T) {
	// OpenSSF Malicious Packages records embed an
	// `malicious-packages-origins` key under database_specific.
	// The signal scan is a substring check on the raw JSON.
	raw := mkRaw(t, map[string]any{
		"id": "GHSA-with-openssf-origin",
		"affected": []any{map[string]any{
			"package":  map[string]any{"name": "openssf-pkg", "ecosystem": "NuGet"},
			"versions": []string{"2.0.0"},
		}},
		"database_specific": map[string]any{
			"malicious-packages-origins": []any{map[string]any{"source": "ossf"}},
		},
	})
	_, status := classifyRecord(raw, "NuGet")
	if status != statusKeptSignal {
		t.Fatalf("status = %v, want statusKeptSignal", status)
	}
}

func TestClassifyRecord_MultipleAffectedPicksFirstEcosystemMatch(t *testing.T) {
	// A GHSA aliased across npm + crates.io should be classified
	// per-ecosystem. Asking for crates.io must NOT pick up the
	// npm entry's versions.
	raw := mkRaw(t, map[string]any{
		"id":      "GHSA-multi",
		"summary": "Compromised package shipped credential stealing payload across registries",
		"affected": []any{
			map[string]any{
				"package":  map[string]any{"name": "shared-name", "ecosystem": "npm"},
				"versions": []string{"9.9.9"},
			},
			map[string]any{
				"package":  map[string]any{"name": "rust-twin", "ecosystem": "crates.io"},
				"versions": []string{"1.0.0"},
			},
		},
	})
	rec, status := classifyRecord(raw, "crates.io")
	if status != statusKeptKeyword {
		t.Fatalf("status = %v, want statusKeptKeyword", status)
	}
	if rec.Name != "rust-twin" {
		t.Errorf("name = %q, want rust-twin (the crates.io entry, not the npm twin)", rec.Name)
	}
	if len(rec.Versions) != 1 || rec.Versions[0] != "1.0.0" {
		t.Errorf("versions = %v, want [1.0.0]", rec.Versions)
	}
}
