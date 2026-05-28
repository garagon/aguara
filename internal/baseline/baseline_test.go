package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/types"
)

func finding(rule, path, matched string) types.Finding {
	return types.Finding{RuleID: rule, FilePath: path, MatchedText: matched, Severity: types.SeverityHigh}
}

func TestFingerprintIsLineIndependent(t *testing.T) {
	a := finding("R1", "a.md", "danger here")
	a.Line = 5
	b := finding("R1", "a.md", "danger here")
	b.Line = 500
	if ComputeFingerprint(a) != ComputeFingerprint(b) {
		t.Fatal("fingerprint changed with line number; must survive line churn")
	}
}

func TestFingerprintNormalizesWhitespace(t *testing.T) {
	a := finding("R1", "a.md", "danger   here")
	b := finding("R1", "a.md", "danger here")
	if ComputeFingerprint(a) != ComputeFingerprint(b) {
		t.Fatal("whitespace reflow changed the fingerprint")
	}
}

func TestFingerprintDistinguishesOccurrences(t *testing.T) {
	// Same rule + file, different matched text must NOT collapse, or
	// baselining one secret/finding would silence a new one.
	a := finding("CRED", "a.md", "key=AAA")
	b := finding("CRED", "a.md", "key=BBB")
	if ComputeFingerprint(a) == ComputeFingerprint(b) {
		t.Fatal("distinct matches collapsed to one fingerprint")
	}
}

func TestFingerprintDistinguishesAnalyzers(t *testing.T) {
	// Two analyzers emitting the same rule ID for the same span must
	// not collapse to one fingerprint.
	a := finding("R1", "a.md", "danger")
	a.Analyzer = "pattern"
	b := finding("R1", "a.md", "danger")
	b.Analyzer = "nlp-injection"
	if ComputeFingerprint(a) == ComputeFingerprint(b) {
		t.Fatal("different analyzers collapsed to one fingerprint")
	}
}

func TestFingerprintNormalizesPathSeparators(t *testing.T) {
	// A baseline written on Windows (backslash paths) must match a scan
	// on a slash-path OS for the same logical file.
	win := finding("R1", `src\app\evil.md`, "danger")
	nix := finding("R1", "src/app/evil.md", "danger")
	if ComputeFingerprint(win) != ComputeFingerprint(nix) {
		t.Fatal("path separators changed the fingerprint; ToSlash normalization missing")
	}
}

func TestBaselineablePredicate(t *testing.T) {
	if !Baselineable(finding("R1", "a.md", "x")) {
		t.Fatal("plain finding should be baselineable")
	}
	sensitive := finding("R1", "a.md", "x")
	sensitive.Sensitive = true
	if Baselineable(sensitive) {
		t.Fatal("sensitive finding must not be baselineable")
	}
	cred := finding("R1", "a.md", "x")
	cred.Category = "credential-leak"
	if Baselineable(cred) {
		t.Fatal("credential-leak finding must not be baselineable")
	}
}

func TestWriteSkipsSensitiveAndDedups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bl.json")
	sensitive := finding("CRED", "a.md", "secret")
	sensitive.Sensitive = true
	findings := []types.Finding{
		finding("R1", "a.md", "danger"),
		finding("R1", "a.md", "danger"), // dup -> one fingerprint
		sensitive,                       // skipped (non-baselineable)
	}
	written, skipped, err := Write(path, findings, "test")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if written != 1 {
		t.Errorf("written = %d, want 1 (dedup)", written)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (sensitive)", skipped)
	}
	// The sensitive snippet must not be derivable from the file.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatal("sensitive matched text leaked into baseline file")
	}
}

func TestLoadFailsClosed(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing baseline must error (fail closed), not return empty")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Fatal("malformed baseline must error")
	}
	wrongVer := filepath.Join(t.TempDir(), "v9.json")
	_ = os.WriteFile(wrongVer, []byte(`{"version":9,"fingerprints":[]}`), 0o644)
	if _, err := Load(wrongVer); err == nil {
		t.Fatal("unknown baseline version must error")
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bl.json")
	f := finding("R1", "a.md", "danger")
	if _, _, err := Write(path, []types.Finding{f}, "test"); err != nil {
		t.Fatal(err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(ComputeFingerprint(f)) {
		t.Fatal("written fingerprint not found after load")
	}
	// Confirm the on-disk shape is the documented version.
	raw, _ := os.ReadFile(path)
	var bf struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(raw, &bf)
	if bf.Version != FileVersion {
		t.Errorf("file version = %d, want %d", bf.Version, FileVersion)
	}
}

func TestApplyPartitions(t *testing.T) {
	known := finding("R1", "a.md", "old danger")
	fresh := finding("R1", "a.md", "new danger")
	sensitive := finding("CRED", "a.md", "secret")
	sensitive.Sensitive = true

	dir := t.TempDir()
	path := filepath.Join(dir, "bl.json")
	if _, _, err := Write(path, []types.Finding{known}, "test"); err != nil {
		t.Fatal(err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	gate, summary := Apply([]types.Finding{known, fresh, sensitive}, set, path)

	if summary.Total != 3 {
		t.Errorf("Total = %d, want 3", summary.Total)
	}
	if summary.Baselined != 1 {
		t.Errorf("Baselined = %d, want 1 (known)", summary.Baselined)
	}
	// New counts only baselineable findings not in the baseline; the
	// sensitive finding is non-baselineable and must NOT inflate New.
	if summary.New != 1 {
		t.Errorf("New = %d, want 1 (fresh only)", summary.New)
	}
	if summary.NonBaselineable != 1 {
		t.Errorf("NonBaselineable = %d, want 1 (sensitive)", summary.NonBaselineable)
	}
	// GateCount = New + NonBaselineable = fresh + sensitive.
	if summary.GateCount != 2 || len(gate) != 2 {
		t.Errorf("GateCount = %d / gate len %d, want 2", summary.GateCount, len(gate))
	}
	for _, g := range gate {
		if ComputeFingerprint(g) == ComputeFingerprint(known) && Baselineable(g) {
			t.Fatal("baselined finding leaked into the gate set")
		}
	}
}
