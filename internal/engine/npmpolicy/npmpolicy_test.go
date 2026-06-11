package npmpolicy

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

func analyze(t *testing.T, relPath, content string) []types.Finding {
	t.Helper()
	a := New()
	out, err := a.Analyze(context.Background(), &scanner.Target{
		RelPath: relPath,
		Content: []byte(content),
	})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	return out
}

func ids(fs []types.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

// ---------------------------------------------------------------------------
// package.json: allowScripts policy

func TestPackageJSON_PinnedAllowNeverFires(t *testing.T) {
	for _, doc := range []string{
		`{"allowScripts": {"esbuild@0.28.0": true}}`,
		`{"allowScripts": {"@scope/pkg@1.2.3": true}}`,
	} {
		if fs := analyze(t, "package.json", doc); len(fs) != 0 {
			t.Errorf("pinned allow fired: %v on %s", ids(fs), doc)
		}
	}
}

func TestPackageJSON_NameOnlyTrueFires(t *testing.T) {
	doc := `{
  "name": "x",
  "allowScripts": {
    "esbuild": true
  }
}`
	fs := analyze(t, "package.json", doc)
	if len(fs) != 1 || fs[0].RuleID != RuleAllowScriptsUnpinned {
		t.Fatalf("want 1 UNPINNED finding, got %v", ids(fs))
	}
	if fs[0].Line != 4 {
		t.Errorf("want line 4, got %d", fs[0].Line)
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("want MEDIUM, got %v", fs[0].Severity)
	}
}

func TestPackageJSON_ScopedNameOnlyTrueFires(t *testing.T) {
	fs := analyze(t, "package.json", `{"allowScripts": {"@scope/pkg": true}}`)
	if len(fs) != 1 || fs[0].RuleID != RuleAllowScriptsUnpinned {
		t.Fatalf("scoped name-only allow should fire UNPINNED, got %v", ids(fs))
	}
}

func TestPackageJSON_DenyEntriesNeverFire(t *testing.T) {
	// npm deny-scripts always writes name-only entries with value false.
	// Ground truth npm 11.16.0: {"esbuild": false}. A deny is a
	// hardening decision and must never be flagged.
	for _, doc := range []string{
		`{"allowScripts": {"esbuild": false}}`,
		`{"allowScripts": {"@scope/pkg": false}}`,
		`{"allowScripts": {"esbuild@0.28.0": false}}`,
	} {
		if fs := analyze(t, "package.json", doc); len(fs) != 0 {
			t.Errorf("deny entry fired: %v on %s", ids(fs), doc)
		}
	}
}

func TestPackageJSON_AbsenceAndOddShapesStaySilent(t *testing.T) {
	for _, doc := range []string{
		`{"name": "x"}`,                        // no allowScripts
		`{"allowScripts": {}}`,                 // empty policy
		`{"allowScripts": {"esbuild": "yes"}}`, // non-bool value: not a shape npm writes
		`{"allowScripts": ["esbuild"]}`,        // wrong type: unmarshal fails, silent
		`{not json`,                            // malformed
		`{"allowScripts": {"*": true}}`,        // wildcard: inert, npm matches no package (ground truth 11.16.0)
		`{"AllowScripts": {"pkg": true}}`,      // mis-cased field: npm reads keys case-sensitively, inert
		`{"allowscripts": {"pkg": true}}`,      // mis-cased field, lowercase variant
		`{"allowScripts": {"pkg name": true}}`, // whitespace: cannot name a package
	} {
		if fs := analyze(t, "package.json", doc); len(fs) != 0 {
			t.Errorf("unexpected findings %v on %s", ids(fs), doc)
		}
	}
}

// ---------------------------------------------------------------------------
// .npmrc

func TestNpmrc_DangerousAllScripts(t *testing.T) {
	fs := analyze(t, ".npmrc", "registry=https://registry.npmjs.org\ndangerously-allow-all-scripts=true\n")
	if len(fs) != 1 || fs[0].RuleID != RuleDangerousAllScripts {
		t.Fatalf("want DANGEROUS finding, got %v", ids(fs))
	}
	if fs[0].Line != 2 {
		t.Errorf("want line 2, got %d", fs[0].Line)
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("want HIGH, got %v", fs[0].Severity)
	}
}

func TestNpmrc_BareKeyReadsAsTrue(t *testing.T) {
	// npm's ini dialect reads a bare `key` line as key=true.
	fs := analyze(t, ".npmrc", "dangerously-allow-all-scripts\n")
	if len(fs) != 1 || fs[0].RuleID != RuleDangerousAllScripts {
		t.Fatalf("bare key should fire, got %v", ids(fs))
	}
}

func TestNpmrc_ExplicitFalseStaysSilent(t *testing.T) {
	for _, line := range []string{
		"dangerously-allow-all-scripts=false",
		"allow-scripts-pin=true",
		"allow-git=none",
		"allow-remote=none",
	} {
		if fs := analyze(t, ".npmrc", line+"\n"); len(fs) != 0 {
			t.Errorf("secure value fired: %v on %q", ids(fs), line)
		}
	}
}

func TestNpmrc_AllowScriptsPinDisabled(t *testing.T) {
	fs := analyze(t, ".npmrc", "allow-scripts-pin=false\n")
	if len(fs) != 1 || fs[0].RuleID != RuleAllowScriptsUnpinned {
		t.Fatalf("want UNPINNED finding, got %v", ids(fs))
	}
}

func TestNpmrc_AllowGitAndRemoteRelaxed(t *testing.T) {
	cases := []struct {
		line string
		rule string
	}{
		{"allow-git=all", RuleAllowGitRelaxed},
		{"allow-git=root", RuleAllowGitRelaxed},
		{"allow-remote=all", RuleAllowRemoteRelaxed},
		{"allow-remote=root", RuleAllowRemoteRelaxed},
		{`allow-git="all"`, RuleAllowGitRelaxed},     // quoted value
		{"  allow-git = all  ", RuleAllowGitRelaxed}, // whitespace
	}
	for _, c := range cases {
		fs := analyze(t, ".npmrc", c.line+"\n")
		if len(fs) != 1 || fs[0].RuleID != c.rule {
			t.Errorf("%q: want %s, got %v", c.line, c.rule, ids(fs))
		}
		if len(fs) == 1 && fs[0].Severity != types.SeverityMedium {
			t.Errorf("%q: want MEDIUM, got %v", c.line, fs[0].Severity)
		}
	}
}

func TestNpmrc_NonHonoredShapesStaySilent(t *testing.T) {
	for _, content := range []string{
		"# dangerously-allow-all-scripts=true\n", // comment
		"; allow-git=all\n",                      // ini comment
		"allow-git=${ALLOW_GIT}\n",               // env expansion: ambiguous
		"allow-git=ALL\n",                        // npm enum values are lowercase
		"allow-git=everything\n",                 // not a documented value
		"[section]\nallow-git=all\n",             // sectioned: npm does not read it
		"some-other-key=true\n",                  // unrelated key
		"allow-git=\"all\" # temporary\n",        // quoted+comment: npm keeps quotes, enum not honored
		"",                                       // empty file
	} {
		if fs := analyze(t, ".npmrc", content); len(fs) != 0 {
			t.Errorf("non-honored shape fired: %v on %q", ids(fs), content)
		}
	}
}

func TestNpmrc_InlineCommentsDoNotMaskValues(t *testing.T) {
	// Ground truth npm 11.16.0: inline comments are stripped from the
	// value, with or without preceding whitespace, so the relaxed
	// setting is still honored and must still fire.
	cases := []struct {
		line string
		rule string
	}{
		{"allow-git=all # temporary exception", RuleAllowGitRelaxed},
		{"dangerously-allow-all-scripts=true ; migration", RuleDangerousAllScripts},
		{"allow-git=all#nospace", RuleAllowGitRelaxed},
		{"allow-remote=root	# tab comment", RuleAllowRemoteRelaxed},
	}
	for _, c := range cases {
		fs := analyze(t, ".npmrc", c.line+"\n")
		if len(fs) != 1 || fs[0].RuleID != c.rule {
			t.Errorf("%q: want %s, got %v", c.line, c.rule, ids(fs))
		}
	}
}

func TestPackageJSON_LineAnchorsInsideAllowScripts(t *testing.T) {
	// The same package name appears under dependencies first; the
	// finding must point at the allowScripts entry, not the dependency.
	doc := `{
  "name": "x",
  "dependencies": {
    "left-pad": "^1.3.0"
  },
  "allowScripts": {
    "left-pad": true
  }
}`
	fs := analyze(t, "package.json", doc)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %v", ids(fs))
	}
	if fs[0].Line != 7 {
		t.Errorf("want line 7 (allowScripts entry), got %d", fs[0].Line)
	}
}

func TestNpmrc_LastWinsPrecedence(t *testing.T) {
	// Ground truth npm 11.16.0: repeated top-level keys resolve to the
	// LAST occurrence. A dangerous value overridden later by a safe one
	// must stay silent; a safe value overridden by a dangerous one fires
	// at the dangerous line.
	if fs := analyze(t, ".npmrc", "allow-git=all\nallow-git=none\n"); len(fs) != 0 {
		t.Errorf("overridden-to-safe fired: %v", ids(fs))
	}
	fs := analyze(t, ".npmrc", "allow-git=none\nallow-git=all\n")
	if len(fs) != 1 || fs[0].Line != 2 {
		t.Errorf("overridden-to-dangerous: want 1 finding at line 2, got %v (line %d)", ids(fs), func() int {
			if len(fs) > 0 {
				return fs[0].Line
			}
			return 0
		}())
	}
}

func TestNpmrc_EmptyBooleanAssignmentReadsAsTrue(t *testing.T) {
	// Ground truth npm 11.16.0: `dangerously-allow-all-scripts=` (empty
	// value) is read as true, same as a bare key.
	fs := analyze(t, ".npmrc", "dangerously-allow-all-scripts=\n")
	if len(fs) != 1 || fs[0].RuleID != RuleDangerousAllScripts {
		t.Fatalf("empty boolean assignment should fire, got %v", ids(fs))
	}
	// Empty ENUM assignment is not a relaxation and stays silent.
	if fs := analyze(t, ".npmrc", "allow-git=\n"); len(fs) != 0 {
		t.Errorf("empty enum assignment fired: %v", ids(fs))
	}
}

func TestPackageJSON_EscapedSlashKeyStillCarriesLine(t *testing.T) {
	// Some serializers escape slashes in JSON strings; json.Unmarshal
	// decodes "@scope\/pkg" to "@scope/pkg". The finding must still
	// point at the entry's line, never line 0.
	doc := "{\n  \"allowScripts\": {\n    \"@scope\\/pkg\": true\n  }\n}"
	fs := analyze(t, "package.json", doc)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %v", ids(fs))
	}
	if fs[0].Line != 3 {
		t.Errorf("want line 3, got %d", fs[0].Line)
	}
}

func TestNpmrc_MultipleFindingsCarryLines(t *testing.T) {
	content := "allow-git=all\n# comment\nallow-remote=all\ndangerously-allow-all-scripts=true\n"
	fs := analyze(t, ".npmrc", content)
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %v", ids(fs))
	}
	wantLines := map[string]int{
		RuleAllowGitRelaxed:     1,
		RuleAllowRemoteRelaxed:  3,
		RuleDangerousAllScripts: 4,
	}
	for _, f := range fs {
		if f.Line != wantLines[f.RuleID] {
			t.Errorf("%s: want line %d, got %d", f.RuleID, wantLines[f.RuleID], f.Line)
		}
	}
}

// ---------------------------------------------------------------------------

func TestNonTargetFilesReturnNil(t *testing.T) {
	for _, p := range []string{"main.go", "pnpm-workspace.yaml", "npmrc", "config/.npmrc.bak"} {
		if fs := analyze(t, p, "allow-git=all\n"); len(fs) != 0 {
			t.Errorf("non-target %q fired: %v", p, ids(fs))
		}
	}
	// nested package.json and .npmrc ARE targets (workspace layouts)
	if fs := analyze(t, "packages/app/.npmrc", "allow-git=all\n"); len(fs) != 1 {
		t.Errorf("nested .npmrc should be a target, got %v", ids(fs))
	}
}

func TestFindingMetadataMatchesCatalog(t *testing.T) {
	// Every emitted finding must carry the catalog's name/severity/
	// category so explain and scan never disagree.
	fs := analyze(t, ".npmrc", "dangerously-allow-all-scripts=true\nallow-git=all\nallow-remote=root\nallow-scripts-pin=false\n")
	if len(fs) != 4 {
		t.Fatalf("want 4 findings, got %v", ids(fs))
	}
	byID := make(map[string]types.Finding)
	for _, f := range fs {
		byID[f.RuleID] = f
	}
	for _, r := range RuleMetadata() {
		f, ok := byID[r.ID]
		if !ok {
			t.Errorf("rule %s not exercised", r.ID)
			continue
		}
		if f.RuleName != r.Name {
			t.Errorf("%s: name %q != catalog %q", r.ID, f.RuleName, r.Name)
		}
		if f.Severity != r.SeverityLevel() {
			t.Errorf("%s: severity %v != catalog %v", r.ID, f.Severity, r.SeverityLevel())
		}
		if f.Category != r.Category {
			t.Errorf("%s: category %q != catalog %q", r.ID, f.Category, r.Category)
		}
		if f.Analyzer != AnalyzerName {
			t.Errorf("%s: analyzer %q != %q", r.ID, f.Analyzer, AnalyzerName)
		}
	}
}
