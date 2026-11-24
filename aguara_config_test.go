package aguara_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara"
)

// writeMarkerRule writes a custom rule that matches the literal marker in
// Markdown files and returns the directory holding it.
func writeMarkerRule(t *testing.T, dir, id, marker string) string {
	t.Helper()
	rule := fmt.Sprintf(`id: %s
name: "%s marker"
description: "Matches %s"
severity: HIGH
category: custom
targets: ["*.md"]
patterns:
  - type: contains
    value: "%s"
`, id, id, marker, marker)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func findingIDs(result *aguara.ScanResult) map[string]int {
	out := map[string]int{}
	for _, f := range result.Findings {
		out[f.RuleID]++
	}
	return out
}

func catalogCount(infos []aguara.RuleInfo, id string) int {
	n := 0
	for _, r := range infos {
		if r.ID == id {
			n++
		}
	}
	return n
}

// TestWithCustomRulesAccumulates covers a consumer that loads its own rule
// pack and then appends a user directory. The second option used to replace
// the first, silently dropping the pack.
func TestWithCustomRulesAccumulates(t *testing.T) {
	base := t.TempDir()
	pack := writeMarkerRule(t, filepath.Join(base, "pack"), "PACK_A_001", "pack-a-marker")
	user := writeMarkerRule(t, filepath.Join(base, "user"), "PACK_B_001", "pack-b-marker")
	content := "pack-a-marker\n\npack-b-marker\n"

	cases := map[string][]aguara.Option{
		"repeated option": {aguara.WithCustomRules(pack), aguara.WithCustomRules(user)},
		"variadic":        {aguara.WithCustomRules(pack, user)},
		"empty entries":   {aguara.WithCustomRules("", pack), aguara.WithCustomRules(user, "")},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := aguara.ScanContent(context.Background(), content, "x.md", opts...)
			if err != nil {
				t.Fatal(err)
			}
			got := findingIDs(result)
			if got["PACK_A_001"] != 1 || got["PACK_B_001"] != 1 {
				t.Fatalf("findings = %v, want one PACK_A_001 and one PACK_B_001", got)
			}

			sc, err := aguara.NewScanner(opts...)
			if err != nil {
				t.Fatal(err)
			}
			listed := sc.ListRules()
			if catalogCount(listed, "PACK_A_001") != 1 || catalogCount(listed, "PACK_B_001") != 1 {
				t.Fatal("scanner catalog must list both custom packs once")
			}
			if catalogCount(aguara.ListRules(opts...), "PACK_A_001") != 1 {
				t.Fatal("ListRules must include the first pack")
			}
			if _, err := aguara.ExplainRule("PACK_A_001", opts...); err != nil {
				t.Fatalf("ExplainRule(PACK_A_001): %v", err)
			}
		})
	}
}

func TestWithCustomRulesSameDirectoryLoadsOnce(t *testing.T) {
	dir := writeMarkerRule(t, t.TempDir(), "PACK_A_001", "pack-a-marker")
	opts := []aguara.Option{aguara.WithCustomRules(dir), aguara.WithCustomRules(dir + string(filepath.Separator))}
	sc, err := aguara.NewScanner(opts...)
	if err != nil {
		t.Fatal(err)
	}
	if n := catalogCount(sc.ListRules(), "PACK_A_001"); n != 1 {
		t.Fatalf("PACK_A_001 listed %d times, want 1", n)
	}
	result, err := sc.ScanContent(context.Background(), "pack-a-marker", "x.md")
	if err != nil {
		t.Fatal(err)
	}
	if got := findingIDs(result)["PACK_A_001"]; got != 1 {
		t.Fatalf("PACK_A_001 findings = %d, want 1", got)
	}
}
