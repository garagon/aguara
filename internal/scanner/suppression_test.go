package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// TestScannerReportsWhatDedupMerged covers a single-line input (a
// serialized tool call) where several rules match the same line: the
// default report keeps one finding, which names the others, and the result
// counts the merge.
func TestScannerReportsWhatDedupMerged(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "call.json"), []byte(`{"cmd":"x"}`), 0o644))

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			{RuleID: "SUPPLY_003", Severity: types.SeverityCritical, Category: "supply-chain", Line: 1, MatchedText: "curl | bash"},
			{RuleID: "CRED_002", Severity: types.SeverityCritical, Category: "credential-leak", Line: 1, MatchedText: "AKIAABCDEFGHIJKLMNOP"},
			{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh, Category: "prompt-injection", Line: 1},
			{RuleID: "EXFIL_005", Severity: types.SeverityHigh, Category: "exfiltration", Line: 1},
			// Same-rule duplicate: merged, counted, not listed.
			{RuleID: "EXFIL_005", Severity: types.SeverityMedium, Category: "exfiltration", Line: 1},
			{RuleID: "UNI_001", Severity: types.SeverityLow, Category: "unicode-attack", Line: 2},
		},
	})
	s.SetRedaction(true)

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 2, "default dedup behavior and counts are unchanged")

	top := result.Findings[0]
	require.Equal(t, "CRED_002", top.RuleID, "rule ID breaks the severity tie, as before")
	require.Equal(t, []types.MergedFinding{
		{RuleID: "SUPPLY_003", Severity: types.SeverityCritical, Category: "supply-chain"},
		{RuleID: "EXFIL_005", Severity: types.SeverityHigh, Category: "exfiltration"},
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh, Category: "prompt-injection"},
	}, top.AlsoMatched, "merged findings are listed by severity then rule ID")
	require.Equal(t, types.RedactedPlaceholder, top.MatchedText)
	require.Empty(t, result.Findings[1].AlsoMatched)

	require.NotNil(t, result.Suppressed)
	require.Equal(t, 4, result.Suppressed.Deduplicated)
	require.Equal(t, 4, result.Suppressed.Findings())
}

func TestScannerAlsoMatchedIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.md"), []byte("x\n"), 0o644))
	findings := []types.Finding{
		{RuleID: "R_C", Severity: types.SeverityHigh, Category: "c", Line: 1},
		{RuleID: "R_A", Severity: types.SeverityHigh, Category: "a", Line: 1},
		{RuleID: "R_B", Severity: types.SeverityMedium, Category: "b", Line: 1},
		{RuleID: "R_D", Severity: types.SeverityCritical, Category: "d", Line: 1},
	}
	var first []types.MergedFinding
	for i := range 20 {
		// Rotate the emit order so map iteration and input order vary.
		rotated := append(append([]types.Finding{}, findings[i%len(findings):]...), findings[:i%len(findings)]...)
		s := scanner.New(4)
		s.RegisterAnalyzer(&mockAnalyzer{name: "test", findings: rotated})
		result, err := s.Scan(context.Background(), dir)
		require.NoError(t, err)
		require.Len(t, result.Findings, 1)
		require.Equal(t, "R_D", result.Findings[0].RuleID)
		if first == nil {
			first = result.Findings[0].AlsoMatched
			continue
		}
		require.Equal(t, first, result.Findings[0].AlsoMatched)
	}
	require.Equal(t, []string{"R_A", "R_C", "R_B"}, []string{first[0].RuleID, first[1].RuleID, first[2].RuleID})
}

func TestScannerCountsEachSuppressionStep(t *testing.T) {
	dir := t.TempDir()
	content := "# aguara-ignore-next-line R_INLINE\nline two\nline three\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(content), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguaraignore"), []byte("skip.md\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skip.md"), []byte("ignored\n"), 0o644))

	s := scanner.New(1)
	s.SetDisabledRules([]string{"R_DISABLED"})
	s.SetMinSeverity(types.SeverityMedium)
	s.SetToolName("Edit")
	s.SetToolScopedRules(map[string]scanner.ToolScopedRule{"R_TOOL": {ExemptTools: []string{"Edit"}}})
	s.RegisterAnalyzer(&onlyFileAnalyzer{file: "test.md", findings: []types.Finding{
		{RuleID: "R_INLINE", Severity: types.SeverityHigh, Line: 2},
		{RuleID: "R_DISABLED", Severity: types.SeverityHigh, Line: 3},
		{RuleID: "R_TOOL", Severity: types.SeverityHigh, Line: 3},
		{RuleID: "R_LOW", Severity: types.SeverityLow, Line: 4},
		{RuleID: "R_KEEP", Severity: types.SeverityHigh, Line: 5},
		{RuleID: "R_DUP", Severity: types.SeverityMedium, Line: 5},
	}})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "R_KEEP", result.Findings[0].RuleID)
	require.Equal(t, &types.SuppressionSummary{
		Deduplicated:     1,
		BelowMinSeverity: 1,
		DisabledRules:    1,
		ToolExemptions:   1,
		InlineDirectives: 1,
		ExcludedFiles:    1,
	}, result.Suppressed)
}

func TestScannerCleanScanStillReportsSuppressionSummary(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.md"), []byte("x\n"), 0o644))
	s := scanner.New(1)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, &types.SuppressionSummary{}, result.Suppressed)
}

func TestScannerSuppressionExcludedFilesWithCallerPatterns(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "vendor"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vendor", "a.md"), []byte("x\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.md"), []byte("x\n"), 0o644))
	s := scanner.New(1)
	s.SetProjectPolicyEnabled(false)
	s.SetIgnorePatterns([]string{"vendor/**"})
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, 1, result.FilesScanned)
	require.Positive(t, result.Suppressed.ExcludedFiles)
}

// onlyFileAnalyzer emits its findings for one file name only.
type onlyFileAnalyzer struct {
	file     string
	findings []types.Finding
}

func (a *onlyFileAnalyzer) Name() string { return "test" }

func (a *onlyFileAnalyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if target.RelPath != a.file {
		return nil, nil
	}
	out := make([]types.Finding, 0, len(a.findings))
	for _, f := range a.findings {
		f.FilePath = target.RelPath
		out = append(out, f)
	}
	return out, nil
}
