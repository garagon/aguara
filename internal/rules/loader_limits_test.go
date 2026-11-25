package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const limitRule = `id: %s
name: Limit rule
severity: LOW
category: custom
remediation: Remove it.
patterns:
  - type: contains
    value: "limit-marker-%s"
examples:
  true_positive:
    - "limit-marker-%s"
  false_positive:
    - "nothing here"
`

func writeLimitRule(t *testing.T, dir, id string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(limitRule, id, id, id)
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lowerLimit[T any](t *testing.T, limit *T, value T) {
	t.Helper()
	old := *limit
	*limit = value
	t.Cleanup(func() { *limit = old })
}

func requireSkipped(t *testing.T, skipped []SkippedFile, path, reason string) {
	t.Helper()
	for _, s := range skipped {
		if s.Path == path && strings.Contains(s.Reason, reason) {
			return
		}
	}
	t.Fatalf("no skipped entry for %s containing %q: %+v", path, reason, skipped)
}

func TestLoadFromDirStopsAtFileAndEntryLimits(t *testing.T) {
	dir := t.TempDir()
	for i := range 5 {
		writeLimitRule(t, dir, fmt.Sprintf("LIM_%03d", i))
	}

	lowerLimit(t, &maxRuleFiles, 3)
	raws, skipped, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 3 {
		t.Fatalf("loaded %d rules, want the first 3", len(raws))
	}
	requireSkipped(t, skipped, dir, "more than 3 rule files")

	lowerLimit(t, &maxRuleFiles, 10000)
	lowerLimit(t, &maxRuleDirEntries, 4) // the directory itself and 3 files
	raws, skipped, err = LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 3 {
		t.Fatalf("loaded %d rules, want 3", len(raws))
	}
	requireSkipped(t, skipped, dir, "more than 4 files and directories")
}

func TestLoadFromDirStopsAtTotalBytes(t *testing.T) {
	dir := t.TempDir()
	writeLimitRule(t, dir, "LIM_A")
	writeLimitRule(t, dir, "LIM_B")
	info, err := os.Stat(filepath.Join(dir, "LIM_A.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lowerLimit(t, &maxRuleBytes, info.Size()+1)
	raws, skipped, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(raws))
	}
	requireSkipped(t, skipped, dir, "in total")
}

func TestLoadFromDirSkipsDirectoriesBelowDepthLimit(t *testing.T) {
	dir := t.TempDir()
	lowerLimit(t, &maxRuleDirDepth, 2)
	writeLimitRule(t, filepath.Join(dir, "a", "b"), "LIM_DEPTH_OK")
	deep := filepath.Join(dir, "a", "b", "c")
	writeLimitRule(t, filepath.Join(deep, "d"), "LIM_DEPTH_DEEP")
	raws, skipped, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || raws[0].ID != "LIM_DEPTH_OK" {
		t.Fatalf("loaded %+v", raws)
	}
	requireSkipped(t, skipped, deep, "more than 2 levels")
}

// The default limits accept a realistic pack: many files a few levels deep.
func TestLoadFromDirDefaultLimitsAcceptRulePacks(t *testing.T) {
	dir := t.TempDir()
	for i := range 300 {
		writeLimitRule(t, filepath.Join(dir, fmt.Sprintf("cat%d", i%10), "sub"), fmt.Sprintf("PACK_%03d", i))
	}
	raws, skipped, err := LoadFromDir(dir)
	if err != nil || len(skipped) != 0 || len(raws) != 300 {
		t.Fatalf("raws=%d skipped=%+v err=%v", len(raws), skipped, err)
	}
}
