package pkgmeta

import (
	"context"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

func analyze(t *testing.T, relPath, content string) []types.Finding {
	t.Helper()
	a := New()
	target := &scanner.Target{
		Path:    relPath,
		RelPath: relPath,
		Content: []byte(content),
	}
	findings, err := a.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	return findings
}

func hasRule(findings []types.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findRule(findings []types.Finding, ruleID string) *types.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// --- target gating ---

func TestIsManifestTarget(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"package.json", true},
		{"./package.json", true},
		{"sub/pkg/package.json", true},
		{"/repo/package.json", true},
		{"package-lock.json", false},
		{"my-package.json", false},
		{"package.json.bak", false},
		{"package.yaml", false},
		{"README.md", false},
	}
	for _, c := range cases {
		got := isManifestTarget(&scanner.Target{Path: c.path, RelPath: c.path})
		if got != c.want {
			t.Errorf("isManifestTarget(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestAnalyzer_NonManifestFile(t *testing.T) {
	findings := analyze(t, "README.md", `# hello`)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-manifest target, got %d", len(findings))
	}
}

func TestAnalyzer_MalformedJSON(t *testing.T) {
	findings := analyze(t, "package.json", `{ "name": broken,`)
	if len(findings) != 0 {
		t.Fatalf("expected analyzer to swallow malformed JSON, got %d findings", len(findings))
	}
}

// --- isGitDep classifier ---

func TestIsGitDep(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		// Git-shaped.
		{"github:owner/repo", true},
		{"git+https://github.com/owner/repo.git", true},
		{"git+ssh://git@github.com/owner/repo.git", true},
		{"git://github.com/owner/repo.git", true},
		{"https://github.com/owner/repo.git", true},
		{"https://github.com/owner/repo.git#abc1234", true},
		{"owner/repo", true},
		{"owner/repo#v1.2.3", true},
		{"gitlab:owner/repo", true},
		{"bitbucket:owner/repo", true},
		{"gist:abcdef0123456789", true},

		// Registry-shaped.
		{"1.2.3", false},
		{"^1.2.3", false},
		{"~1.2.3", false},
		{">=1.0.0 <2.0.0", false},
		{"latest", false},
		{"next", false},
		{"*", false},
		{"npm:@scope/alias@1.0.0", false},
		{"file:../local", false},
		{"link:../local", false},
		{"workspace:*", false},

		// Edge.
		{"", false},
		{"   ", false},
		{"@scope/pkg@1.0.0", false},
		{"owner/repo/subpath", false}, // two slashes
	}
	for _, c := range cases {
		got := isGitDep(c.version)
		if got != c.want {
			t.Errorf("isGitDep(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

// --- isSuspiciousPackageName classifier ---

func TestIsSuspiciousPackageName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"setup", true},
		{"install", true},
		{"runner", true},
		{"runtime", true},
		{"bootstrap", true},
		{"loader", true},
		{"setup-utils", true},
		{"node-setup", true},
		{"setup_helper", true},
		{"@scope/setup", true},
		{"@scope/setup-tools", true},

		// Not suspicious. "setuptools" is "setup" followed by alphabetic
		// "tools" — the analyzer requires a non-alpha boundary so it does
		// not flag setuptools-* libraries.
		{"react", false},
		{"lodash", false},
		{"@scope/lodash", false},
		{"setuptools-clone", false},
	}
	for _, c := range cases {
		got := isSuspiciousPackageName(c.name)
		if got != c.want {
			t.Errorf("isSuspiciousPackageName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// --- NPM_LIFECYCLE_GIT_001 ---

func TestSafe_LifecycleAlone(t *testing.T) {
	// Lifecycle script alone is fine (husky/prepare is normal).
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"prepare": "husky install"},
  "dependencies": {"react": "^18.0.0"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleLifecycleGit) {
		t.Errorf("lifecycle alone should not trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

func TestSafe_GitDepAlone(t *testing.T) {
	// Git dep alone (no lifecycle script) is not the chain.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"test": "vitest"},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleLifecycleGit) {
		t.Errorf("git dep alone should not trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

func TestVuln_LifecycleGit_Standard(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node ./hook.js"},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleLifecycleGit)
	if f == nil {
		t.Fatalf("expected NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("standard chain should be HIGH, got %v", f.Severity)
	}
}

func TestVuln_LifecycleGit_OptionalSuspiciousIsCritical(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"prepare": "node ./setup.js"},
  "optionalDependencies": {"setup": "github:owner/setup"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleLifecycleGit)
	if f == nil {
		t.Fatalf("expected NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("optional + suspicious name + lifecycle should be CRITICAL, got %v", f.Severity)
	}
}

func TestVuln_LifecycleGit_AllSections(t *testing.T) {
	// devDeps with git source should also chain.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"preinstall": "node hook.js"},
  "devDependencies": {"dev-lib": "git+https://github.com/owner/dev-lib.git"}
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("devDeps git + lifecycle should trigger, got: %+v", findings)
	}
}

// --- NPM_OPTIONAL_GIT_001 ---

func TestSafe_OptionalRegistryDep(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "optionalDependencies": {"fsevents": "^2.3.0"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleOptionalGit) {
		t.Errorf("registry-pinned optional dep should not trigger NPM_OPTIONAL_GIT_001, got: %+v", findings)
	}
}

func TestVuln_OptionalGit_MediumByDefault(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "optionalDependencies": {"my-helper": "github:owner/my-helper"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleOptionalGit)
	if f == nil {
		t.Fatalf("expected NPM_OPTIONAL_GIT_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityMedium {
		t.Errorf("plain optional git dep should be MEDIUM, got %v", f.Severity)
	}
}

func TestVuln_OptionalGit_HighOnSuspiciousName(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "optionalDependencies": {"runtime": "github:owner/runtime"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleOptionalGit)
	if f == nil {
		t.Fatalf("expected NPM_OPTIONAL_GIT_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("optional git dep with suspicious name should be HIGH, got %v", f.Severity)
	}
}

// --- NPM_PUBLISH_SURFACE_001 ---

func TestSafe_PublishConfigAlone(t *testing.T) {
	// publishConfig alone is fine; many libraries set it.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"access": "public"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("publishConfig alone should not trigger NPM_PUBLISH_SURFACE_001, got: %+v", findings)
	}
}

func TestSafe_PublishScriptWithoutInstallContext(t *testing.T) {
	// publish script + no install/build/test in scripts AND no provenance/OIDC string.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"release": "npm publish"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("publish script alone should not chain, got: %+v", findings)
	}
}

func TestVuln_PublishSurface_FullChain(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true, "access": "public"},
  "scripts": {
    "build": "npm run compile",
    "release": "npm publish --provenance"
  }
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RulePublishSurface)
	if f == nil {
		t.Fatalf("expected NPM_PUBLISH_SURFACE_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("publish surface chain should be HIGH, got %v", f.Severity)
	}
}

func TestVuln_PublishSurface_OIDCStringInScripts(t *testing.T) {
	// Mention of id-token / OIDC anywhere in the manifest counts as a
	// trusted-publishing reference for the chain.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {
    "build": "npm run compile",
    "publish:ci": "echo ACTIONS_ID_TOKEN_REQUEST_URL=$ACTIONS_ID_TOKEN_REQUEST_URL && npm publish"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("publish + install/build + id-token reference should chain, got: %+v", findings)
	}
}

// --- line anchors ---

func TestFindLineOfQuotedKey(t *testing.T) {
	raw := []byte("{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"build\": \"tsc\"\n  }\n}\n")
	cases := []struct {
		key  string
		want int
	}{
		{"name", 2},
		{"version", 3},
		{"scripts", 4},
		{"build", 5},
		{"missing", 0},
	}
	for _, c := range cases {
		got := findLineOfQuotedKey(raw, c.key)
		if got != c.want {
			t.Errorf("findLineOfQuotedKey(_, %q) = %d, want %d", c.key, got, c.want)
		}
	}
}

func TestFindingsHaveDistinctLines(t *testing.T) {
	// The scanner's default dedup mode drops cross-rule duplicates on the
	// same (file, line) pair, so the three pkgmeta rules MUST anchor at
	// distinct lines or two of them disappear from output.
	pkg := `{
  "name": "x",
  "version": "1.0.0",
  "publishConfig": {"provenance": true, "access": "public"},
  "scripts": {
    "postinstall": "node ./hook.js",
    "build": "npm run compile",
    "release": "npm publish --provenance"
  },
  "optionalDependencies": {
    "setup": "github:owner/setup"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if len(findings) < 3 {
		t.Fatalf("expected three findings on full chain, got %d: %+v", len(findings), findings)
	}
	seen := map[int]string{}
	for _, f := range findings {
		if prev, ok := seen[f.Line]; ok {
			t.Errorf("two findings collide on line %d: %s and %s", f.Line, prev, f.RuleID)
		}
		seen[f.Line] = f.RuleID
		if f.Line == 0 {
			t.Errorf("%s has no line anchor", f.RuleID)
		}
	}
}

// --- finding shape regression ---

func TestFindingsHaveStableFields(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true},
  "scripts": {
    "postinstall": "node ./hook.js",
    "build": "npm run compile",
    "release": "npm publish --provenance"
  },
  "optionalDependencies": {"setup": "github:owner/setup"}
}`
	findings := analyze(t, "package.json", pkg)
	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}
	for _, f := range findings {
		if f.Analyzer != AnalyzerName {
			t.Errorf("finding %s: analyzer = %q, want %q", f.RuleID, f.Analyzer, AnalyzerName)
		}
		if f.Category != "supply-chain" {
			t.Errorf("finding %s: category = %q, want supply-chain", f.RuleID, f.Category)
		}
		if !strings.HasPrefix(f.RuleID, "NPM_") {
			t.Errorf("finding ruleID %q should have NPM_ prefix", f.RuleID)
		}
		if f.Confidence == 0 {
			t.Errorf("finding %s: confidence should be > 0", f.RuleID)
		}
		if f.Remediation == "" {
			t.Errorf("finding %s: remediation should be non-empty", f.RuleID)
		}
		if f.FilePath != "package.json" {
			t.Errorf("finding %s: file path = %q, want package.json", f.RuleID, f.FilePath)
		}
	}
}
