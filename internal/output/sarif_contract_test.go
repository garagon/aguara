package output_test

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/baseline"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/schematest"
	"github.com/garagon/aguara/internal/types"
)

// The SARIF 2.1.0 schema is the OASIS errata 01 file, vendored from
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
// (SHA-256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e).
const sarifSchema = "testdata/sarif-schema-2.1.0.json"

func contractResult() *types.ScanResult {
	return &types.ScanResult{
		FilesScanned: 3,
		Verdict:      types.VerdictBlock,
		RiskScore:    87.50000000000001,
		Suppressed:   &types.SuppressionSummary{Deduplicated: 2},
		Findings: []types.Finding{
			{
				RuleID: "CRED_002", RuleName: "AWS access key", Severity: types.SeverityCritical,
				Category: "credential-leak", FilePath: "config/aws.env", Line: 4,
				MatchedText: types.RedactedPlaceholder, Analyzer: "pattern",
			},
			{
				RuleID: "MCP_009", RuleName: "Capability escalation", Severity: types.SeverityHigh,
				Category: "mcp-attack", FilePath: "mcp.json", Line: 7, Column: 12,
				MatchedText: "capabilities: SYS_ADMIN", Analyzer: "mcp-capability", Confidence: 0.9900000000000001,
				BaselineState: baseline.StateBaselined,
			},
			{
				RuleID: "EXTDL_013", RuleName: "Curl or wget piped to shell", Severity: types.SeverityMedium,
				Category: "external-download", FilePath: "SKILL.md", Line: 10,
				MatchedText: "curl x | sh", Analyzer: "pattern", BaselineState: baseline.StateNew,
				AlsoMatched: []types.MergedFinding{{RuleID: "SUPPLY_003", Severity: types.SeverityMedium, Category: "supply-chain"}},
			},
			{
				RuleID: "NLP_AUTHORITY_CLAIM", RuleName: "Authority-claim language in untrusted content",
				Severity: types.SeverityLow, Category: "prompt-injection", FilePath: "SKILL.md", Line: 2,
				MatchedText: "the maintainer says", Analyzer: "nlp",
			},
			{
				RuleID: "TEAM_001", RuleName: "Team rule", Severity: types.SeverityInfo,
				Category: "custom", FilePath: "notes.md", Line: 1, MatchedText: "internal-only", Analyzer: "pattern",
			},
		},
	}
}

func contractCatalog() map[string]rulemeta.Rule {
	return rulemeta.Index([]rulemeta.Rule{
		{ID: "CRED_002", Name: "AWS access key", Description: "Detects AWS access key IDs", Remediation: "Rotate the key.", CWE: []string{"CWE-798"}},
		{ID: "MCP_009", Name: "Capability escalation", Description: "Broad capability grants.", Remediation: "Drop the capability."},
		{ID: "EXTDL_013", Name: "Curl or wget piped to shell", Description: "Pipe to shell.", Remediation: "Download, verify, then run.", CWE: []string{"CWE-494"}},
		// The NLP finding carries no remediation; the catalog supplies it.
		{ID: "NLP_AUTHORITY_CLAIM", Name: "Authority-claim language in untrusted content", Description: "Unverifiable authority.", Remediation: "Route through a verified channel."},
		{ID: "TEAM_001", Name: "Team rule", Description: "Custom.", Remediation: "Fix it."},
	})
}

func formatSARIF(t *testing.T, result *types.ScanResult, ext []output.SARIFExternalResult, opts output.SARIFOptions) (map[string]any, []byte) {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, output.WriteSARIF(&buf, result, ext, opts))
	schematest.Validate(t, schematest.Load(t, sarifSchema), buf.Bytes())
	var log map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
	return log["runs"].([]any)[0].(map[string]any), buf.Bytes()
}

func TestSARIFRulesCarrySecuritySeverityHelpAndCWE(t *testing.T) {
	builtin := map[string]bool{"CRED_002": true, "MCP_009": true, "EXTDL_013": true, "NLP_AUTHORITY_CLAIM": true}
	run, _ := formatSARIF(t, contractResult(), nil, output.SARIFOptions{Catalog: contractCatalog(), BuiltinRules: builtin})
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	byID := map[string]map[string]any{}
	for _, r := range rules {
		rule := r.(map[string]any)
		byID[rule["id"].(string)] = rule
	}
	wantScore := map[string]string{"CRED_002": "9.5", "MCP_009": "8.0", "EXTDL_013": "5.5", "NLP_AUTHORITY_CLAIM": "2.0", "TEAM_001": "0.0"}
	for id, score := range wantScore {
		rule := byID[id]
		props := rule["properties"].(map[string]any)
		require.Equal(t, score, props["security-severity"], id)
		require.Contains(t, props["tags"], "security", id)
		require.Equal(t, rule["fullDescription"].(map[string]any)["text"], contractCatalog()[id].Description, id)
		help := rule["help"].(map[string]any)
		require.Contains(t, help["text"], contractCatalog()[id].Remediation, id)
		require.Contains(t, help["markdown"], "aguara explain "+id, id)
	}
	// The category tag stays first, as before.
	require.Equal(t, "credential-leak", byID["CRED_002"]["properties"].(map[string]any)["tags"].([]any)[0])
	require.Contains(t, byID["CRED_002"]["properties"].(map[string]any)["tags"], "external/cwe/cwe-798")
	require.Equal(t, output.RuleCatalogURI+"#cred_002", byID["CRED_002"]["helpUri"], "each built-in rule links to its own RULES.md row")
	require.NotContains(t, byID["TEAM_001"], "helpUri", "custom rules are not in the public catalog")

	rel := byID["EXTDL_013"]["relationships"].([]any)[0].(map[string]any)
	require.Equal(t, "494", rel["target"].(map[string]any)["id"])
	taxa := run["taxonomies"].([]any)[0].(map[string]any)
	require.Equal(t, "CWE", taxa["name"])
	require.Len(t, taxa["taxa"], 2)
}

func TestSARIFResultsKeepFingerprintsAndReportRealColumns(t *testing.T) {
	result := contractResult()
	run, _ := formatSARIF(t, result, nil, output.SARIFOptions{Catalog: contractCatalog(), URIPrefix: "skills", InWorkTree: true})
	results := run["results"].([]any)
	require.Len(t, results, len(result.Findings))
	for i, r := range results {
		res := r.(map[string]any)
		f := result.Findings[i]
		loc := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		art := loc["artifactLocation"].(map[string]any)
		require.Equal(t, "skills/"+f.FilePath, art["uri"])
		require.Equal(t, output.SourceRootBaseID, art["uriBaseId"])
		region := loc["region"].(map[string]any)
		require.Equal(t, float64(f.Line), region["startLine"])
		if f.Column > 0 {
			require.Equal(t, float64(f.Column), region["startColumn"])
		} else {
			require.NotContains(t, region, "startColumn", "no invented column")
		}
		require.NotContains(t, region, "endColumn")
		if baseline.Baselineable(f) {
			require.Equal(t, string(baseline.ComputeFingerprint(f)), res["partialFingerprints"].(map[string]any)["aguara/v1"],
				"fingerprints use the finding path, not the repository-relative URI")
		} else {
			require.NotContains(t, res, "partialFingerprints")
		}
	}
	mcp := results[1].(map[string]any)
	require.Equal(t, "unchanged", mcp["baselineState"])
	require.Equal(t, 0.99, mcp["properties"].(map[string]any)["confidence"])
	require.Equal(t, float64(99), mcp["properties"].(map[string]any)["rank"])
	extdl := results[2].(map[string]any)
	require.Equal(t, "new", extdl["baselineState"])
	require.NotEmpty(t, extdl["properties"].(map[string]any)["also_matched"])
	require.Equal(t, "note", extdl["level"], "levels are unchanged: MEDIUM and LOW stay note")

	props := run["properties"].(map[string]any)
	require.Equal(t, 87.5, props["riskScore"])
	require.Equal(t, "block", props["verdict_label"])
	require.NotNil(t, props["suppressed"])
}

func TestSARIFEmptyRunAndInvocation(t *testing.T) {
	run, _ := formatSARIF(t, &types.ScanResult{}, nil, output.SARIFOptions{})
	require.Equal(t, []any{}, run["results"])
	require.Equal(t, []any{}, run["tool"].(map[string]any)["driver"].(map[string]any)["rules"])
	inv := run["invocations"].([]any)[0].(map[string]any)
	require.Equal(t, true, inv["executionSuccessful"])
	require.Equal(t, []any{}, inv["toolExecutionNotifications"])
	require.NotContains(t, inv, "exitCode", "without an invocation the exit code is unknown")
	require.NotContains(t, run, "automationDetails")
	require.NotContains(t, run, "originalUriBaseIds")
}

// A later change can report an incomplete scan by setting
// ExecutionSuccessful false and adding notifications.
func TestSARIFInvocationNotifications(t *testing.T) {
	run, _ := formatSARIF(t, &types.ScanResult{}, nil, output.SARIFOptions{
		Category: "pkg-a",
		Invocation: &output.SARIFInvocation{
			ExecutionSuccessful: false,
			ExitCode:            2,
			ExitCodeDescription: "scan incomplete",
			Notifications: []output.SARIFNotification{
				{Level: "error", Message: "could not read big.bin", URI: "big.bin"},
				{Level: "warning", Message: "skipped", RuleID: "CHECK_COMPROMISED_PACKAGE"},
			},
		},
	})
	inv := run["invocations"].([]any)[0].(map[string]any)
	require.Equal(t, false, inv["executionSuccessful"])
	require.Equal(t, float64(2), inv["exitCode"])
	require.Len(t, inv["toolExecutionNotifications"], 2)
	require.Equal(t, "pkg-a/", run["automationDetails"].(map[string]any)["id"])
}

func TestSARIFExternalResults(t *testing.T) {
	run, _ := formatSARIF(t, nil, []output.SARIFExternalResult{{
		RuleID: "CHECK_COMPROMISED_PACKAGE", RuleName: "Known malicious package", RuleDescription: "desc",
		Remediation: "remove", Category: "supply-chain", HelpURI: "https://example.com/docs",
		Severity: types.SeverityCritical, Message: "node-ipc 9.2.3 is compromised", URI: "package-lock.json",
		FingerprintKey: "aguara/package/v1", Fingerprint: "abc", Properties: map[string]any{"package": "node-ipc"},
	}}, output.SARIFOptions{})
	res := run["results"].([]any)[0].(map[string]any)
	require.Equal(t, "abc", res["partialFingerprints"].(map[string]any)["aguara/package/v1"])
	require.Equal(t, "node-ipc", res["properties"].(map[string]any)["package"])
	region := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
	require.Equal(t, float64(1), region["startLine"], "a whole-file result points at line 1")
}

func TestSecuritySeverityBands(t *testing.T) {
	// GitHub: over 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
	require.Equal(t, "9.5", output.SecuritySeverity(types.SeverityCritical))
	require.Equal(t, "8.0", output.SecuritySeverity(types.SeverityHigh))
	require.Equal(t, "5.5", output.SecuritySeverity(types.SeverityMedium))
	require.Equal(t, "2.0", output.SecuritySeverity(types.SeverityLow))
	require.Equal(t, "0.0", output.SecuritySeverity(types.SeverityInfo))
}

func TestEncodeURIPath(t *testing.T) {
	for in, want := range map[string]string{
		"skills/demo/SKILL.md": "skills/demo/SKILL.md",
		"my skill/SKILL.md":    "my%20skill/SKILL.md",
		"100%.md":              "100%25.md",
		"a#b?c.md":             "a%23b%3Fc.md",
		"caf\u00e9/\u65e5.md":  "caf%C3%A9/%E6%97%A5.md",
		"-leading-dash.md":     "-leading-dash.md",
		"c:not-a-scheme.md":    "c%3Anot-a-scheme.md",
		"./a/./b.md":           "a/b.md",
		"../outside.md":        "outside.md",
		"a/../../escape.md":    "escape.md",
		"/abs/path.md":         "abs/path.md",
		"back\\slash.md":       "back%5Cslash.md",
	} {
		got := output.EncodeURIPath(in)
		require.Equal(t, want, got, in)
		require.True(t, schematest.IsURIReference(got), got)
		u, err := url.Parse(got)
		require.NoError(t, err)
		require.Empty(t, u.Scheme, "a relative reference, never a scheme: %s", got)
		require.False(t, strings.HasPrefix(got, "/"), "never absolute: %s", got)
		require.NotContains(t, "/"+got+"/", "/../", "never climbs: %s", got)
	}
}

// Unusual file names produce valid URI references, while fingerprints
// still come from the finding's own path.
func TestSARIFEncodesArtifactURIsButNotFingerprints(t *testing.T) {
	names := []string{"my skill/SKILL.md", "100%.md", "a#b?.md", "caf\u00e9.md", "-dash.md"}
	result := &types.ScanResult{}
	for _, name := range names {
		result.Findings = append(result.Findings, types.Finding{
			RuleID: "PROMPT_INJECTION_001", RuleName: "Instruction override attempt", Severity: types.SeverityCritical,
			Category: "prompt-injection", FilePath: name, Line: 1, MatchedText: "Ignore all previous instructions", Analyzer: "pattern",
		})
	}
	run, _ := formatSARIF(t, result, nil, output.SARIFOptions{URIPrefix: "skills", InWorkTree: true})
	for i, r := range run["results"].([]any) {
		res := r.(map[string]any)
		uri := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
		decoded, err := url.PathUnescape(uri)
		require.NoError(t, err)
		require.Equal(t, "skills/"+names[i], decoded)
		require.Equal(t, string(baseline.ComputeFingerprint(result.Findings[i])), res["partialFingerprints"].(map[string]any)["aguara/v1"])
	}
}

func TestSARIFNotificationsReferenceOnlyRunRules(t *testing.T) {
	ext := []output.SARIFExternalResult{{
		RuleID: "CHECK_COMPROMISED_PACKAGE", RuleName: "Known malicious package", Category: "supply-chain",
		Severity: types.SeverityCritical, Message: "m", URI: "package-lock.json",
	}}
	run, _ := formatSARIF(t, nil, ext, output.SARIFOptions{Invocation: &output.SARIFInvocation{
		ExecutionSuccessful: true,
		Notifications: []output.SARIFNotification{
			{Level: "warning", RuleID: "CHECK_COMPROMISED_PACKAGE", Message: "in the run"},
			{Level: "warning", RuleID: "CHECK_PERSISTENCE_ARTIFACT", Message: "outside the repository"},
		},
	}})
	notes := run["invocations"].([]any)[0].(map[string]any)["toolExecutionNotifications"].([]any)
	first := notes[0].(map[string]any)
	require.Equal(t, map[string]any{"id": "CHECK_COMPROMISED_PACKAGE", "index": float64(0)}, first["associatedRule"])
	second := notes[1].(map[string]any)
	require.NotContains(t, second, "associatedRule", "a rule that is not in driver.rules is not referenced")
	require.Equal(t, "CHECK_PERSISTENCE_ARTIFACT: outside the repository", second["message"].(map[string]any)["text"])
}

func TestSARIFRunPropertiesHoldNoLocalAbsolutePaths(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "home", "runner", "work", "repo")
	other := filepath.Join(string(filepath.Separator), "tmp", "elsewhere")
	result := &types.ScanResult{Baseline: &types.BaselineSummary{Applied: true, Path: filepath.Join(other, "baseline.json")}}
	_, raw := formatSARIF(t, result, nil, output.SARIFOptions{
		LocalRoots: []string{root},
		Properties: map[string]any{
			"coverage": map[string]any{
				"unsupported_evidence": []any{
					map[string]any{"path": filepath.Join(root, "deno.lock"), "kind": "lockfile"},
					map[string]any{"path": filepath.Join(other, "gems.locked"), "kind": "lockfile"},
				},
			},
			"note": "could not read " + filepath.Join(root, "sub", "x.txt"),
		},
		Invocation: &output.SARIFInvocation{ExitCode: 2, ExitCodeDescription: "scan failed: " + filepath.Join(root, "big.bin"),
			Notifications: []output.SARIFNotification{{Level: "error", Message: "read " + filepath.Join(root, "big.bin")}}},
	})
	text := string(raw)
	require.NotContains(t, text, root)
	require.NotContains(t, text, other)
	require.Contains(t, text, `"path": "deno.lock"`)
	require.Contains(t, text, "could not read sub/x.txt")
	require.Contains(t, text, "scan failed: big.bin")
	require.Contains(t, text, `"applied": true`, "the baseline summary stays, only its outside path goes")
}

func TestSARIFCWETagsArePadded(t *testing.T) {
	result := &types.ScanResult{Findings: []types.Finding{
		{RuleID: "THIRDPARTY_006", RuleName: "Unescaped user input in HTML output", Severity: types.SeverityHigh, Category: "third-party-content", FilePath: "a.js", Line: 1},
		{RuleID: "MCP_012", RuleName: "Prototype pollution vector", Severity: types.SeverityHigh, Category: "mcp-attack", FilePath: "b.js", Line: 1},
	}}
	catalog := rulemeta.Index([]rulemeta.Rule{
		{ID: "THIRDPARTY_006", CWE: []string{"CWE-79"}},
		{ID: "MCP_012", CWE: []string{"CWE-1321"}},
	})
	run, _ := formatSARIF(t, result, nil, output.SARIFOptions{Catalog: catalog})
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	require.Contains(t, rules[0].(map[string]any)["properties"].(map[string]any)["tags"], "external/cwe/cwe-079")
	require.Contains(t, rules[1].(map[string]any)["properties"].(map[string]any)["tags"], "external/cwe/cwe-1321")
	taxa := run["taxonomies"].([]any)[0].(map[string]any)["taxa"].([]any)
	require.Equal(t, "79", taxa[0].(map[string]any)["id"], "taxon IDs are the CWE number")
}

// Every built-in rule's helpUri anchor exists in RULES.md.
func TestRuleHelpAnchorsExistInRulesMarkdown(t *testing.T) {
	data, err := os.ReadFile("../../RULES.md")
	require.NoError(t, err)
	doc := string(data)
	ids := rulecatalog.BuiltinIDs()
	require.NotEmpty(t, ids)
	for id := range ids {
		require.Contains(t, doc, `<a id="`+output.RuleAnchor(id)+`"></a>`+id+" |", "RULES.md has no anchor for %s", id)
		require.Equal(t, output.RuleCatalogURI+"#"+output.RuleAnchor(id), output.RuleHelpURI(id))
	}
}
