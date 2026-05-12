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
		{"https://git.example.com/team/pkg.git", true},
		{"https://git.example.com/team/pkg.git#v1", true},
		{"ssh://git@gitlab.com/group/pkg.git", true},
		// Non-.git HTTPS URLs are not git deps (could be tarball etc.).
		{"https://gitlab.com/group/pkg", false},
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
		got := findLineOfQuotedKey(raw, c.key)
		if got != c.want {
			t.Errorf("findLineOfQuotedKey(_, %q) = %d, want %d", c.key, got, c.want)
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
