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

// --- pass-8 edge case: whitespace-tolerant anchor ---

func TestFindDepLine_TolerantOfWhitespaceBeforeColon(t *testing.T) {
	// Valid JSON allows whitespace between a key and its colon. The
	// anchor lookup must not regress to line 0 just because the
	// manifest is formatted with " : " instead of ":".
	raw := []byte("{\n  \"name\": \"x\",\n  \"optionalDependencies\" : {\n    \"alpha\" : \"github:owner/alpha\",\n    \"bravo\" : \"github:owner/bravo\"\n  }\n}\n")
	if got := findDepLine(raw, "optionalDependencies", "alpha"); got == 0 {
		t.Errorf("findDepLine should tolerate whitespace before colon for alpha, got 0")
	}
	if got := findDepLine(raw, "optionalDependencies", "bravo"); got == 0 {
		t.Errorf("findDepLine should tolerate whitespace before colon for bravo, got 0")
	}
}

func TestOptionalGit_WhitespaceFormattedManifestKeepsDistinctLines(t *testing.T) {
	// Valid JSON with spaces before colons must still produce one
	// finding per optional git dep with distinct line anchors.
	pkg := "{\n  \"name\": \"x\",\n  \"optionalDependencies\" : {\n    \"alpha\" : \"github:owner/alpha\",\n    \"bravo\" : \"github:owner/bravo\"\n  }\n}"
	findings := analyze(t, "package.json", pkg)
	count := 0
	lines := map[int]string{}
	for _, f := range findings {
		if f.RuleID != RuleOptionalGit {
			continue
		}
		count++
		if f.Line == 0 {
			t.Errorf("whitespace-formatted manifest dropped anchor to line 0: %s", f.MatchedText)
		}
		if prev, ok := lines[f.Line]; ok {
			t.Errorf("two findings collide on line %d (also %s)", f.Line, prev)
		}
		lines[f.Line] = f.MatchedText
	}
	if count != 2 {
		t.Errorf("expected 2 NPM_OPTIONAL_GIT_001 findings, got %d: %+v", count, findings)
	}
}

// --- pass-7 edge cases: provenance opt-out + section-scoped anchor ---

func TestHasEnabledProvenanceFlag(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"npm publish --provenance", true},
		{"npm publish --provenance=true", true},
		{"npm publish --provenance --tag next", true},
		{"npm publish --provenance=false", false},
		{"npm publish --provenance=0", false},
		// Multiple instances: any one enabling counts.
		{"npm publish --provenance=false && other-cmd --provenance", true},
		// Substring without prefix dashes does not count.
		{"npm provenance check", false},
		{"", false},
	}
	for _, c := range cases {
		got := hasEnabledProvenanceFlag(c.s)
		if got != c.want {
			t.Errorf("hasEnabledProvenanceFlag(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestPublishSurface_ProvenanceFalseFlagDoesNotTrigger(t *testing.T) {
	// `npm publish --provenance=false` is an explicit opt-out and must
	// not be read as a trust-publishing reference.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {
    "build": "tsc",
    "release": "npm publish --provenance=false"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("--provenance=false must not chain, got: %+v", findings)
	}
}

func TestFindDepLine_ScopedToSection(t *testing.T) {
	// When a string token appears multiple times in the manifest (here
	// the package "name" matches a dep name, and a script key matches a
	// dep name), findDepLine must point at the dependency entry inside
	// the named section, not the first occurrence.
	raw := []byte(`{
  "name": "setup",
  "version": "1.0.0",
  "scripts": {
    "setup": "tsc"
  },
  "dependencies": {
    "setup": "github:owner/setup"
  }
}`)
	got := findDepLine(raw, "dependencies", "setup")
	// "dependencies": { is on line 7; the "setup" key inside is line 8.
	if got != 8 {
		t.Errorf("findDepLine(dependencies, setup) = %d, want 8", got)
	}
	// Lookup in a section that does not contain the dep returns 0.
	if got := findDepLine(raw, "optionalDependencies", "setup"); got != 0 {
		t.Errorf("findDepLine(optionalDependencies, setup) = %d, want 0", got)
	}
}

func TestLifecycleGit_AnchorIgnoresPackageName(t *testing.T) {
	// A package whose name matches one of its own dependency names must
	// emit the finding on the dependency line, not on the package "name"
	// line, so inline-ignore directives target the right entry.
	pkg := `{
  "name": "setup",
  "version": "1.0.0",
  "scripts": {"postinstall": "node hook.js"},
  "dependencies": {"setup": "github:owner/setup"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleLifecycleGit)
	if f == nil {
		t.Fatalf("expected NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
	if f.Line != 5 {
		t.Errorf("expected anchor on dependency entry line (5), got line %d", f.Line)
	}
}

// --- shorthand edge cases (P2 from pass-6 review) ---

func TestIsGitDep_LocalPathNotGit(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"./runner", false},
		{"../setup", false},
		{"/abs/path/to/pkg", false},
		{"~/path/to/pkg", false},
		// Make sure path detection does not over-reach.
		{"owner/repo", true},
	}
	for _, c := range cases {
		got := isGitDep(c.version)
		if got != c.want {
			t.Errorf("isGitDep(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestSafe_LocalPathDepNoLifecycleGit(t *testing.T) {
	// "runner": "./runner" is a local filesystem dep, not a git source.
	// Even with a lifecycle script and a suspicious-looking optional
	// name, the chain must not fire.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node hook.js"},
  "optionalDependencies": {"runner": "./runner"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleLifecycleGit) {
		t.Errorf("local path dep must not chain lifecycle-git, got: %+v", findings)
	}
	if hasRule(findings, RuleOptionalGit) {
		t.Errorf("local path optional dep must not chain optional-git, got: %+v", findings)
	}
}

func TestIsGitDep_SemverFragmentShorthand(t *testing.T) {
	// npm accepts shorthands with a semver fragment, e.g.
	// "some-lib": "owner/repo#semver:^1.2.3". The ^ lives in the fragment
	// and must not disqualify the core.
	cases := []struct {
		version string
		want    bool
	}{
		{"owner/repo#semver:^1.2.3", true},
		{"owner/repo#semver:~2.0.0", true},
		{"owner/repo#v1.2.3", true},
		// Range chars OUTSIDE a fragment still disqualify.
		{"owner/repo^1.2.3", false},
	}
	for _, c := range cases {
		got := isGitDep(c.version)
		if got != c.want {
			t.Errorf("isGitDep(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestLifecycleGit_SemverFragmentShorthandChain(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node hook.js"},
  "dependencies": {"some-lib": "owner/repo#semver:^1.2.3"}
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("semver-fragment shorthand should chain, got: %+v", findings)
	}
}

// --- OIDC false-positive guard (P2 from pass-5 review) ---

func TestPublishSurface_OIDCDependencyNameDoesNotTrigger(t *testing.T) {
	// "oidc-client-ts" is a real npm library; its mere presence as a
	// dependency must not be read as a trusted-publishing signal. With
	// publishConfig + build script, the rule would previously falsely
	// upgrade purely because the substring "oidc" appeared in the
	// dependency name.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"access": "public"},
  "scripts": {
    "build": "tsc",
    "release": "npm publish"
  },
  "dependencies": {
    "oidc-client-ts": "^3"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("oidc-* dep name must not chain publish-surface, got: %+v", findings)
	}
}

func TestPublishSurface_IDTokenSubstringInDepNameDoesNotTrigger(t *testing.T) {
	// Same guard for "id-token" / "id_token" appearing as part of a real
	// dependency name (e.g. jwt-id-token-handler).
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"access": "public"},
  "scripts": {
    "build": "tsc",
    "release": "npm publish"
  },
  "dependencies": {
    "jwt-id-token-handler": "^1"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("id-token substring in dep name must not chain, got: %+v", findings)
	}
}

// --- lifecycle / provenance edge cases (P2 from pass-4 review) ---

func TestLifecycle_PrepublishIsInstallTime(t *testing.T) {
	// npm still executes prepublish during install/ci (deprecated but
	// active). Manifests that combine prepublish with a git source must
	// still chain.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"prepublish": "node ./hook.js"},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("prepublish runs during install and must trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

func TestLifecycle_EmptyBodyDoesNotTrigger(t *testing.T) {
	// A placeholder lifecycle entry with an empty body does not execute
	// project code; declaring it must not fail --ci scans.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": ""},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleLifecycleGit) {
		t.Errorf("empty postinstall body must not trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

func TestPublishSurface_ProvenanceFalseDoesNotTrigger(t *testing.T) {
	// Explicit opt-out should not falsely upgrade the publish-surface
	// chain just because the literal string "provenance" appears in the
	// raw manifest text.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": false, "access": "public"},
  "scripts": {
    "build": "tsc",
    "release": "npm publish"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("provenance:false must not chain, got: %+v", findings)
	}
}

func TestPublishSurface_ProvenanceTrueTriggers(t *testing.T) {
	// Explicit opt-in via publishConfig is the canonical enabling form.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true, "access": "public"},
  "scripts": {
    "build": "tsc",
    "release": "npm publish"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("provenance:true should chain, got: %+v", findings)
	}
}

func TestPublishSurface_OIDCWithoutProvenanceFlagTriggers(t *testing.T) {
	// Trust-publishing references other than provenance (id-token, OIDC
	// env vars) still count even when provenance:false is set.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": false},
  "scripts": {
    "build": "tsc",
    "release": "ACTIONS_ID_TOKEN_REQUEST_URL=$URL npm publish"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("OIDC env reference should still chain even with provenance:false, got: %+v", findings)
	}
}

// --- additional credential redaction / script-key coverage (P2 from pass-3 review) ---

func TestSanitizeGitURL_TrimsBeforeMatching(t *testing.T) {
	// isGitDep trims surrounding whitespace, so sanitizeGitURL must too;
	// otherwise the leading space breaks the HasPrefix check and the
	// credential survives into Description / MatchedText.
	cases := []struct {
		in   string
		want string
	}{
		{" git+https://user:token@github.com/org/repo.git ", "git+https://github.com/org/repo.git"},
		{"\thttps://user:tok@gitlab.com/group/repo.git", "https://gitlab.com/group/repo.git"},
	}
	for _, c := range cases {
		got := sanitizeGitURL(c.in)
		if got != c.want {
			t.Errorf("sanitizeGitURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLifecycleGit_RedactsCredentialedWhitespaceURL(t *testing.T) {
	// End-to-end check: a dependency value with surrounding whitespace
	// must not leak its credential into a finding.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node hook.js"},
  "dependencies": {"some-lib": " git+https://user:s3cret@github.com/owner/repo.git "}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleLifecycleGit)
	if f == nil {
		t.Fatalf("expected NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
	if strings.Contains(f.Description, "s3cret") || strings.Contains(f.MatchedText, "s3cret") {
		t.Errorf("credential leaked through whitespace-padded value: desc=%q matched=%q", f.Description, f.MatchedText)
	}
}

func TestPublishSurface_BuildScriptKeyCounts(t *testing.T) {
	// `"build": "tsc"` is a build step even though the body contains no
	// package-manager verb. publish surface + provenance + build script
	// must chain.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true},
  "scripts": {
    "build": "tsc",
    "release": "npm publish --provenance"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("'build: tsc' should count as install/build for publish-surface chain, got: %+v", findings)
	}
}

func TestPublishSurface_TestScriptKeyCounts(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true},
  "scripts": {
    "test": "vitest",
    "release": "npm publish --provenance"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("'test: vitest' should count for publish-surface chain, got: %+v", findings)
	}
}

func TestPublishSurface_EmptyScriptBodyDoesNotCount(t *testing.T) {
	// A `build` key with an empty body is not actually executable; do not
	// upgrade publish-surface on it.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true},
  "scripts": {
    "build": "",
    "release": "npm publish --provenance"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RulePublishSurface) {
		t.Errorf("empty build body must not count as install/build, got: %+v", findings)
	}
}

// --- lifecycle hook accuracy (P2 from pass-2 review) ---

func TestLifecycle_PrepublishOnlyNotInstallTime(t *testing.T) {
	// prepublishOnly runs only on `npm publish`, not on `npm install`.
	// A manifest with a git dep and a prepublishOnly script must not
	// produce a HIGH/CRITICAL lifecycle-git finding; doing so creates a
	// false positive that fails CI under --fail-on high.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"prepublishOnly": "npm run build"},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleLifecycleGit) {
		t.Errorf("prepublishOnly is publish-only and must not trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

func TestLifecycle_PrepackNotInstallTime(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"prepack": "npm run build"},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleLifecycleGit) {
		t.Errorf("prepack is publish-only and must not trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

func TestLifecycle_PreprepareIsInstallTime(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"preprepare": "node ./hook.js"},
  "dependencies": {"some-lib": "github:owner/repo"}
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("preprepare runs during install and must trigger NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
}

// --- non-GitHub git URLs (P2 from pass-2 review) ---

func TestIsGitDep_NonGitHubHosts(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"https://gitlab.com/group/pkg.git", true},
		{"https://gitlab.com/group/pkg.git#abc1234", true},
		{"https://bitbucket.org/team/pkg.git", true},
		// Ground truth npm 11.16.0: a .git URL on an UNKNOWN host is a
		// remote dependency (EALLOWREMOTE), not git - npm only treats
		// http(s) as git via hosted-git-info domains or a git+ scheme.
		{"https://git.example.com/team/pkg.git", false},
		{"https://git.example.com/team/pkg.git#v1", false},
		{"git+https://git.example.com/team/pkg.git", true},
		{"ssh://git@gitlab.com/group/pkg.git", true},
		// Repo-root HTTPS URLs on hosted-git domains ARE git deps:
		// ground truth npm 11.16.0 normalizes them to git+https specs
		// and gates them with EALLOWGIT, not EALLOWREMOTE.
		{"https://gitlab.com/group/pkg", true},
		{"https://github.com/owner/repo", true},
		// Deeper paths on the same hosts stay remote tarballs
		// (EALLOWREMOTE): archives, release downloads, tarball
		// endpoints, codeload.
		{"https://github.com/org/repo/archive/main.tar.gz", false},
		{"https://github.com/org/repo/releases/download/v1/pkg.tgz", false},
		{"https://github.com/org/repo/tarball/main", false},
		{"https://codeload.github.com/org/repo/tar.gz/main", false},
		// /tree/<ref> is a git committish (EALLOWGIT).
		{"https://github.com/org/repo/tree/main", true},
		// userinfo and port do not change the classification.
		{"https://token123@github.com/org/repo.git", true},
		{"https://github.com:443/org/repo.git", true},
		// gitlab subgroups are git; gitlab /-/ download endpoints are not.
		{"https://gitlab.com/group/subgroup/repo", true},
		{"https://gitlab.com/group/repo/-/archive/main/repo-main.tar.gz", false},
		// Unknown hosts without .git stay non-git.
		{"https://git.example.com/group/pkg", false},
		// HTTPS to a registry-shaped URL is not a git dep.
		{"https://registry.npmjs.org/some-pkg/-/some-pkg-1.0.0.tgz", false},
	}
	for _, c := range cases {
		got := isGitDep(c.version)
		if got != c.want {
			t.Errorf("isGitDep(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestLifecycleGit_GitLabSource(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node ./hook.js"},
  "dependencies": {"some-lib": "https://gitlab.com/group/some-lib.git#abc"}
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("gitlab .git URL should classify as git source, got: %+v", findings)
	}
}

// --- credential redaction (P1 from prior review) ---

func TestSanitizeGitURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Strip user:token@host from URL forms.
		{"git+https://user:token@github.com/org/repo.git", "git+https://github.com/org/repo.git"},
		{"git+ssh://user@github.com/org/repo.git", "git+ssh://github.com/org/repo.git"},
		{"https://abc123:x-oauth-basic@github.com/org/repo.git", "https://github.com/org/repo.git"},
		// Preserve non-credentialed URLs.
		{"git+https://github.com/org/repo.git", "git+https://github.com/org/repo.git"},
		{"github:org/repo", "github:org/repo"},
		{"org/repo#abc1234", "org/repo#abc1234"},
		// `@` in a scoped name path must not be confused with userinfo.
		{"https://github.com/@scope/repo.git", "https://github.com/@scope/repo.git"},
		// Registry strings pass through unchanged.
		{"^1.2.3", "^1.2.3"},
		{"", ""},
	}
	for _, c := range cases {
		got := sanitizeGitURL(c.in)
		if got != c.want {
			t.Errorf("sanitizeGitURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLifecycleGit_RedactsCredentialedURL(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node ./hook.js"},
  "dependencies": {"some-lib": "git+https://user:s3cret@github.com/owner/repo.git"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleLifecycleGit)
	if f == nil {
		t.Fatalf("expected NPM_LIFECYCLE_GIT_001, got: %+v", findings)
	}
	// Detector output must not echo the credentials.
	if strings.Contains(f.Description, "s3cret") || strings.Contains(f.MatchedText, "s3cret") {
		t.Errorf("credentials leaked through finding: desc=%q matched=%q", f.Description, f.MatchedText)
	}
	if strings.Contains(f.Description, "user:") || strings.Contains(f.MatchedText, "user:") {
		t.Errorf("userinfo leaked through finding: desc=%q matched=%q", f.Description, f.MatchedText)
	}
}

func TestOptionalGit_RedactsCredentialedURL(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "optionalDependencies": {"runner": "git+https://user:tok@github.com/owner/runner.git"}
}`
	findings := analyze(t, "package.json", pkg)
	f := findRule(findings, RuleOptionalGit)
	if f == nil {
		t.Fatalf("expected NPM_OPTIONAL_GIT_001, got: %+v", findings)
	}
	if strings.Contains(f.Description, "tok") || strings.Contains(f.MatchedText, "tok") {
		t.Errorf("credentials leaked: desc=%q matched=%q", f.Description, f.MatchedText)
	}
}

// --- optional-git dedup correctness (P2 from prior review) ---

func TestOptionalGit_MultipleDepsKeepDistinctLines(t *testing.T) {
	// Same-rule dedup uses (file, ruleID, line). Two NPM_OPTIONAL_GIT_001
	// findings must anchor at distinct lines so neither is silently dropped.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "optionalDependencies": {
    "alpha": "github:owner/alpha",
    "bravo": "github:owner/bravo"
  }
}`
	findings := analyze(t, "package.json", pkg)
	count := 0
	lines := map[int]string{}
	for _, f := range findings {
		if f.RuleID != RuleOptionalGit {
			continue
		}
		count++
		if prev, ok := lines[f.Line]; ok {
			t.Errorf("two NPM_OPTIONAL_GIT_001 findings collide on line %d (also %s)", f.Line, prev)
		}
		lines[f.Line] = f.MatchedText
	}
	if count != 2 {
		t.Fatalf("expected 2 NPM_OPTIONAL_GIT_001 findings, got %d: %+v", count, findings)
	}
}

func TestOptionalGit_SuppressedWhenLifecycleCovers(t *testing.T) {
	// When a lifecycle script is present, NPM_LIFECYCLE_GIT_001 already
	// covers every optional git dep with stronger severity. The optional
	// rule must stay quiet to avoid a cross-rule collision the scanner's
	// default dedup would silently resolve.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "scripts": {"postinstall": "node ./hook.js"},
  "optionalDependencies": {"setup": "github:owner/setup"}
}`
	findings := analyze(t, "package.json", pkg)
	if hasRule(findings, RuleOptionalGit) {
		t.Errorf("lifecycle script should suppress NPM_OPTIONAL_GIT_001, got: %+v", findings)
	}
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("expected NPM_LIFECYCLE_GIT_001 to fire on the same dep, got: %+v", findings)
	}
}

// --- publish surface install shorthand (P2 from prior review) ---

func TestPublishSurface_NpmInstallShorthand(t *testing.T) {
	// "npm i" alone in a script body is a valid install step; the
	// publish-surface chain must recognize it.
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true},
  "scripts": {
    "setup": "npm i",
    "release": "npm publish --provenance"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("\"npm i\" alone should count as install; expected NPM_PUBLISH_SURFACE_001, got: %+v", findings)
	}
}

func TestPublishSurface_PnpmInstallShorthand(t *testing.T) {
	pkg := `{
  "name": "x", "version": "1.0.0",
  "publishConfig": {"provenance": true},
  "scripts": {
    "setup": "pnpm i",
    "release": "pnpm publish"
  }
}`
	findings := analyze(t, "package.json", pkg)
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("\"pnpm i\" alone should count as install, got: %+v", findings)
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
		got := findKeyLine(raw, c.key)
		if got != c.want {
			t.Errorf("findKeyLine(_, %q) = %d, want %d", c.key, got, c.want)
		}
	}
}

func TestFindingsHaveDistinctLines(t *testing.T) {
	// The scanner's default dedup mode drops cross-rule duplicates on the
	// same (file, line) pair. With lifecycle suppression of OPTIONAL_GIT,
	// a full-chain manifest emits LIFECYCLE_GIT (on the dep entry) and
	// PUBLISH_SURFACE (on publishConfig). They must anchor at distinct
	// lines so the scanner keeps both.
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
	if !hasRule(findings, RuleLifecycleGit) {
		t.Errorf("expected NPM_LIFECYCLE_GIT_001 on full chain, got: %+v", findings)
	}
	if !hasRule(findings, RulePublishSurface) {
		t.Errorf("expected NPM_PUBLISH_SURFACE_001 on full chain, got: %+v", findings)
	}
	if hasRule(findings, RuleOptionalGit) {
		t.Errorf("expected NPM_OPTIONAL_GIT_001 to be suppressed when lifecycle covers, got: %+v", findings)
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
		// pkgmeta emits the NPM_* chain rules plus SUPPLY_026 (npm
		// lifecycle runs local JS), which was moved here from a flat
		// YAML rule.
		if !strings.HasPrefix(f.RuleID, "NPM_") && f.RuleID != RuleLocalJSLifecycle {
			t.Errorf("finding ruleID %q should be an NPM_* rule or %s", f.RuleID, RuleLocalJSLifecycle)
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

// TestLocalJSLifecycle_SUPPLY026 covers the rule moved here from a flat
// YAML regex. Walking the parsed scripts map fixes the two failure modes
// the regex had: a `}` in a sibling script value (brace case) and a
// same-named key outside the scripts object (FP case).
func TestLocalJSLifecycle_SUPPLY026(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"preinstall node file", `{"scripts":{"preinstall":"node index.js"}}`, true},
		{"install node mjs", `{"scripts":{"install":"node ./scripts/setup.mjs"}}`, true},
		{"postinstall node cjs", `{"scripts":{"postinstall":"node scripts/install.cjs"}}`, true},
		{"preinstall node inline eval", `{"scripts":{"preinstall":"node -e \"require('child_process').exec('id')\""}}`, true},
		{"prepare bun run", `{"scripts":{"prepare":"bun run index.js"}}`, true},
		{"postinstall bun file", `{"scripts":{"postinstall":"bun ./setup.mjs"}}`, true},
		{"preprepare node (bypass key)", `{"scripts":{"preprepare":"node x.js"}}`, true},
		{"shell-prefixed node", `{"scripts":{"postinstall":"cd lib && node build.js"}}`, true},
		{"node with flags before file", `{"scripts":{"postinstall":"node --require dotenv/config ./index.js"}}`, true},
		{"extensionless node path", `{"scripts":{"preinstall":"node ./scripts/setup"}}`, true},
		{"extensionless bare relative path", `{"scripts":{"postinstall":"node dist/main"}}`, true},
		// codex #2: a brace-bearing shell expansion in an earlier script
		// must not hide a later malicious hook (the regex `[^}]*` failed here).
		{"brace in sibling script", `{"scripts":{"prebuild":"echo ${npm_package_name}","postinstall":"node index.js"}}`, true},
		// false positives
		{"build is not a lifecycle hook", `{"scripts":{"build":"node index.js"}}`, false},
		{"test is not a lifecycle hook", `{"scripts":{"test":"node test.js"}}`, false},
		{"husky", `{"scripts":{"postinstall":"husky install"}}`, false},
		{"only-allow", `{"scripts":{"preinstall":"npx only-allow pnpm"}}`, false},
		{"node version probe", `{"scripts":{"postinstall":"node --version"}}`, false},
		// codex #2 FP: lifecycle-named key OUTSIDE the scripts object.
		{"install key under config", `{"config":{"install":"node index.js"}}`, false},
		{"no scripts at all", `{"name":"x","version":"1.0.0"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hasRule(analyze(t, "package.json", c.content), RuleLocalJSLifecycle)
			if got != c.want {
				t.Errorf("SUPPLY_026 present = %v, want %v", got, c.want)
			}
		})
	}
}

// TestLocalJSLifecycle_LineAnchoredToScripts locks the line anchor to the
// scripts entry, not a same-named key earlier in the manifest.
func TestLocalJSLifecycle_LineAnchoredToScripts(t *testing.T) {
	content := "{\n" + // line 1
		"  \"dependencies\": {\n" + // 2
		"    \"install\": \"^1.0.0\"\n" + // 3 (decoy: dep named "install")
		"  },\n" + // 4
		"  \"scripts\": {\n" + // 5
		"    \"install\": \"node index.js\"\n" + // 6 (the real hook)
		"  }\n" + // 7
		"}" // 8
	findings := analyze(t, "package.json", content)
	var line int
	found := false
	for _, f := range findings {
		if f.RuleID == RuleLocalJSLifecycle {
			line, found = f.Line, true
			break
		}
	}
	if !found {
		t.Fatalf("expected SUPPLY_026, got %+v", findings)
	}
	if line != 6 {
		t.Errorf("SUPPLY_026 line = %d, want 6 (scripts entry, not the dep on line 3)", line)
	}
}

// ---------------------------------------------------------------------------
// npm v12 install-trust readiness

func readinessIDs(fs []types.Finding) (git, remote int) {
	for _, f := range fs {
		switch f.RuleID {
		case RuleGitInstallTrust:
			git++
		case RuleRemoteInstallTrust:
			remote++
		}
	}
	return
}

func TestInstallTrustReadiness_GitAndRemoteDeps(t *testing.T) {
	doc := `{
  "name": "x",
  "dependencies": {
    "a": "github:owner/repo",
    "b": "https://example.com/pkg-1.0.0.tgz",
    "c": "^1.0.0"
  },
  "devDependencies": {
    "d": "git+https://github.com/o/r.git"
  }
}`
	fs := analyze(t, "package.json", doc)
	git, remote := readinessIDs(fs)
	if git != 2 || remote != 1 {
		t.Fatalf("want 2 git + 1 remote readiness findings, got git=%d remote=%d (%v)", git, remote, func() []string {
			var o []string
			for _, f := range fs {
				o = append(o, f.RuleID)
			}
			return o
		}())
	}
	for _, f := range fs {
		if f.RuleID == RuleGitInstallTrust || f.RuleID == RuleRemoteInstallTrust {
			if f.Severity != types.SeverityInfo {
				t.Errorf("%s: want INFO, got %v", f.RuleID, f.Severity)
			}
			if f.Line == 0 {
				t.Errorf("%s: missing line anchor", f.RuleID)
			}
		}
	}
}

func TestInstallTrustReadiness_SuppressedByStrongerGitRules(t *testing.T) {
	// With a lifecycle script present, NPM_LIFECYCLE_GIT_001 covers every
	// git dep at higher severity; git readiness stays silent. Remote
	// readiness has no stronger sibling and still fires.
	doc := `{
  "name": "x",
  "scripts": {"postinstall": "node setup.js"},
  "dependencies": {
    "a": "github:owner/repo",
    "b": "https://example.com/pkg-1.0.0.tgz"
  }
}`
	fs := analyze(t, "package.json", doc)
	git, remote := readinessIDs(fs)
	if git != 0 {
		t.Errorf("git readiness should be suppressed under lifecycle scripts, got %d", git)
	}
	if remote != 1 {
		t.Errorf("want 1 remote readiness finding, got %d", remote)
	}
	// optionalDependencies git deps stay with NPM_OPTIONAL_GIT_001 only.
	doc2 := `{"name":"x","optionalDependencies":{"a":"github:owner/repo"}}`
	fs2 := analyze(t, "package.json", doc2)
	git2, _ := readinessIDs(fs2)
	if git2 != 0 {
		t.Errorf("optionalDependencies git dep should not double-fire readiness, got %d", git2)
	}
	hasOptional := false
	for _, f := range fs2 {
		if f.RuleID == RuleOptionalGit {
			hasOptional = true
		}
	}
	if !hasOptional {
		t.Errorf("NPM_OPTIONAL_GIT_001 expected for optional git dep")
	}
}

func TestInstallTrustReadiness_LocalSourcesStaySilent(t *testing.T) {
	// npm v12 keeps allow-file / allow-directory defaults, so file:,
	// link:, workspace: and local paths are not readiness findings.
	doc := `{
  "name": "x",
  "dependencies": {
    "a": "file:../local",
    "b": "link:../linked",
    "c": "workspace:*",
    "d": "./vendored",
    "e": "^2.0.0"
  }
}`
	fs := analyze(t, "package.json", doc)
	git, remote := readinessIDs(fs)
	if git != 0 || remote != 0 {
		t.Errorf("local sources fired readiness: git=%d remote=%d", git, remote)
	}
}

func TestInstallTrustReadiness_RemoteURLCredentialsRedacted(t *testing.T) {
	// Signed URLs and query-string auth must never reach finding output.
	doc := `{"name":"x","dependencies":{"blob":"https://user:secret@cdn.example.com/blob.tgz?token=hunter2supersecret"}}`
	fs := analyze(t, "package.json", doc)
	for _, f := range fs {
		if f.RuleID != RuleRemoteInstallTrust {
			continue
		}
		for _, field := range []string{f.Description, f.MatchedText} {
			if containsAny(field, "hunter2supersecret", "secret@") {
				t.Fatalf("credential leaked into finding output: %q", field)
			}
		}
		return
	}
	t.Fatal("expected a remote readiness finding")
}

func TestInstallTrustReadiness_GitURLCredentialsRedacted(t *testing.T) {
	doc := `{"name":"x","dependencies":{"viz":"git+https://cdn.example.com/repo.git?token=hunter2supersecret"}}`
	fs := analyze(t, "package.json", doc)
	for _, f := range fs {
		if f.RuleID != RuleGitInstallTrust {
			continue
		}
		if containsAny(f.Description+f.MatchedText, "hunter2supersecret") {
			t.Fatalf("credential leaked into git readiness output")
		}
		return
	}
	t.Fatal("expected a git readiness finding")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestInstallTrustReadiness_HostedHTTPSURLsAreGitNotRemote(t *testing.T) {
	// Ground truth npm 11.16.0: a bare https URL on a known git host is
	// normalized to a git spec and gated by EALLOWGIT, so the readiness
	// advice must point at allow-git, not allow-remote.
	doc := `{"name":"x","dependencies":{
  "a": "https://github.com/org/repo",
  "b": "https://gitlab.com/org/repo",
  "c": "https://cdn.example.com/repo.git?token=secret123abc",
  "d": "https://cdn.example.com/pkg-1.0.0.tgz"
}}`
	fs := analyze(t, "package.json", doc)
	git, remote := readinessIDs(fs)
	// c (.git on unknown host) is a REMOTE dep per npm ground truth.
	if git != 2 || remote != 2 {
		t.Fatalf("want 2 git + 2 remote, got git=%d remote=%d", git, remote)
	}
}
