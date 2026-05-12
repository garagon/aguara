package ci

import (
	"context"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// analyze runs the analyzer against an in-memory workflow at the given
// relative path. Returns the resulting findings.
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

func TestIsWorkflowTarget(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{".github/workflows/ci.yml", true},
		{".github/workflows/release.yaml", true},
		{"a/b/.github/workflows/x.yml", true},
		{"/repo/.github/workflows/x.YML", true},
		{".github/workflows/README.md", false},
		{"workflows/ci.yml", false},
		{".github/actions/ci.yml", false},
		{"package.json", false},
	}
	for _, c := range cases {
		got := isWorkflowTarget(&scanner.Target{Path: c.path, RelPath: c.path})
		if got != c.want {
			t.Errorf("isWorkflowTarget(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestAnalyzer_NonWorkflowFile(t *testing.T) {
	findings := analyze(t, "README.md", "# hello")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-workflow target, got %d", len(findings))
	}
}

func TestAnalyzer_MalformedYaml(t *testing.T) {
	// `:` without value triggers a yaml parse error in many cases; use a
	// blatant mapping/scalar mixup instead.
	findings := analyze(t, ".github/workflows/bad.yml", "jobs:\n  - this is a sequence not a map\n")
	if len(findings) != 0 {
		t.Fatalf("expected analyzer to swallow malformed yaml, got %d findings", len(findings))
	}
}

// --- safe workflows ---

func TestSafe_PullRequestBuild(t *testing.T) {
	wf := `
name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      - run: npm test
`
	findings := analyze(t, ".github/workflows/ci.yml", wf)
	if len(findings) != 0 {
		t.Fatalf("safe pull_request build should produce no findings, got %d: %+v", len(findings), findings)
	}
}

func TestSafe_PullRequestTargetCommentOnly(t *testing.T) {
	// pull_request_target without checking out PR code and without
	// install/build/test should not flag.
	wf := `
name: PR Comment
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({...})
`
	findings := analyze(t, ".github/workflows/comment.yml", wf)
	if hasRule(findings, RulePwnRequest) {
		t.Fatalf("safe pull_request_target should not trigger PWN_REQUEST, got: %+v", findings)
	}
}

func TestSafe_PullRequestTargetBaseCheckout(t *testing.T) {
	// Checking out the base ref (default actions/checkout behavior on
	// pull_request_target) is safe — only PR head checkout enables the chain.
	wf := `
name: PR Hello
on: pull_request_target
jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Hello PR ${{ github.event.pull_request.number }}"
`
	findings := analyze(t, ".github/workflows/hello.yml", wf)
	if len(findings) != 0 {
		t.Fatalf("base-ref checkout of pull_request_target should be clean, got %d findings", len(findings))
	}
}

func TestSafe_PublishOnlyOIDCJob(t *testing.T) {
	// Publish-only job with id-token: write is the *intended* use of OIDC.
	// No install/build/test → no finding.
	wf := `
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm publish --provenance
`
	findings := analyze(t, ".github/workflows/release.yml", wf)
	if hasRule(findings, RuleOIDC) {
		t.Fatalf("publish-only OIDC job should not trigger OIDC rule, got: %+v", findings)
	}
}

func TestSafe_TopLevelOIDCButJobOverridesToNone(t *testing.T) {
	// Top-level id-token: write, but the executing job overrides to id-token: none.
	wf := `
name: Build
on: push
permissions:
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: none
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: pnpm install
      - run: pnpm test
`
	findings := analyze(t, ".github/workflows/build.yml", wf)
	if hasRule(findings, RuleOIDC) {
		t.Fatalf("job override id-token: none should suppress OIDC rule, got: %+v", findings)
	}
}

// --- vulnerable workflows ---

func TestVuln_PwnRequest_Basic(t *testing.T) {
	wf := `
name: Bundle Size
on: pull_request_target
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pnpm install
      - run: pnpm build
`
	findings := analyze(t, ".github/workflows/bundle-size.yml", wf)
	f := findRule(findings, RulePwnRequest)
	if f == nil {
		t.Fatalf("expected GHA_PWN_REQUEST_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("expected HIGH for default pwn-request, got %v", f.Severity)
	}
	if f.Analyzer != AnalyzerName {
		t.Errorf("expected analyzer %q, got %q", AnalyzerName, f.Analyzer)
	}
	if f.Category != "supply-chain" {
		t.Errorf("expected category supply-chain, got %q", f.Category)
	}
	if f.Line == 0 {
		t.Errorf("expected non-zero line anchor, got 0")
	}
	if f.Remediation == "" {
		t.Errorf("expected non-empty remediation text")
	}
}

func TestVuln_PwnRequest_EscalatedByWritePerms(t *testing.T) {
	// Same chain but with id-token: write → CRITICAL.
	wf := `
name: Bundle
on: pull_request_target
permissions:
  id-token: write
  contents: read
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - run: yarn install
      - run: yarn build
`
	findings := analyze(t, ".github/workflows/bundle.yml", wf)
	f := findRule(findings, RulePwnRequest)
	if f == nil {
		t.Fatalf("expected GHA_PWN_REQUEST_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL with id-token: write, got %v", f.Severity)
	}
}

func TestVuln_PwnRequest_PlusCache(t *testing.T) {
	wf := `
name: Cached Bundle
on: pull_request_target
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install
`
	findings := analyze(t, ".github/workflows/cached-bundle.yml", wf)
	if !hasRule(findings, RulePwnRequest) {
		t.Errorf("expected PWN_REQUEST, got: %+v", findings)
	}
	cache := findRule(findings, RuleCache)
	if cache == nil {
		t.Fatalf("expected GHA_CACHE_001, got: %+v", findings)
	}
	if cache.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL for cache+install chain, got %v", cache.Severity)
	}
}

func TestSafe_CacheRestoreOnly(t *testing.T) {
	// actions/cache/restore is read-only. A pull_request_target job that
	// only restores cache cannot poison a downstream workflow, so the
	// cache-write primitive that GHA_CACHE_001 requires is absent.
	wf := `
on: pull_request_target
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache/restore@v4
        with:
          path: ~/.cache
          key: shared-cache
`
	findings := analyze(t, ".github/workflows/restore.yml", wf)
	if hasRule(findings, RuleCache) {
		t.Errorf("actions/cache/restore should not trigger GHA_CACHE_001, got: %+v", findings)
	}
}

func TestVuln_CacheSaveExplicit(t *testing.T) {
	// actions/cache/save is the write half. Keep flagging it.
	wf := `
on: pull_request_target
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: pr-cache
`
	findings := analyze(t, ".github/workflows/save.yml", wf)
	if !hasRule(findings, RuleCache) {
		t.Errorf("actions/cache/save should trigger GHA_CACHE_001, got: %+v", findings)
	}
}

func TestVuln_CacheWithoutCodeExecution(t *testing.T) {
	// Untrusted checkout + cache step but no install/build/test → still HIGH
	// because cache write can be poisoned regardless.
	wf := `
name: Cache Poison
on: pull_request_target
jobs:
  cache_only:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: pr-${{ github.event.pull_request.number }}
`
	findings := analyze(t, ".github/workflows/cache.yml", wf)
	cache := findRule(findings, RuleCache)
	if cache == nil {
		t.Fatalf("expected GHA_CACHE_001 without install, got: %+v", findings)
	}
	if cache.Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", cache.Severity)
	}
}

func TestVuln_OIDC_InstallBuildPublish(t *testing.T) {
	wf := `
name: Publish
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pnpm install
      - run: pnpm build
      - run: pnpm publish
`
	findings := analyze(t, ".github/workflows/publish.yml", wf)
	f := findRule(findings, RuleOIDC)
	if f == nil {
		t.Fatalf("expected GHA_OIDC_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("install+build+publish in OIDC job should be CRITICAL, got %v", f.Severity)
	}
}

func TestVuln_OIDC_WriteAll(t *testing.T) {
	wf := `
name: Build
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      - run: npm test
`
	findings := analyze(t, ".github/workflows/build.yml", wf)
	if !hasRule(findings, RuleOIDC) {
		t.Errorf("write-all should trigger OIDC rule when install/build runs, got: %+v", findings)
	}
}

func TestVuln_Checkout_NoPersistFalse(t *testing.T) {
	wf := `
name: PR Hot Take
on: pull_request_target
jobs:
  ht:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cat README.md
`
	findings := analyze(t, ".github/workflows/ht.yml", wf)
	if !hasRule(findings, RuleCheckout) {
		t.Errorf("PR head checkout without persist-credentials: false should flag GHA_CHECKOUT_001, got: %+v", findings)
	}
}

func TestSafe_Checkout_PersistFalse(t *testing.T) {
	wf := `
name: PR Hot Take
on: pull_request_target
jobs:
  ht:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: cat README.md
`
	findings := analyze(t, ".github/workflows/ht.yml", wf)
	if hasRule(findings, RuleCheckout) {
		t.Errorf("persist-credentials: false should suppress GHA_CHECKOUT_001, got: %+v", findings)
	}
}

// --- event-shape coverage ---

func TestEventShapes(t *testing.T) {
	cases := []struct {
		name string
		on   string
	}{
		{"scalar", "on: pull_request_target"},
		{"sequence", "on: [push, pull_request_target]"},
		{"mapping", "on:\n  pull_request_target:\n    types: [opened, synchronize]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wf := c.on + `
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pnpm install
`
			findings := analyze(t, ".github/workflows/x.yml", wf)
			if !hasRule(findings, RulePwnRequest) {
				t.Errorf("event shape %q failed to trigger PWN_REQUEST, got: %+v", c.name, findings)
			}
		})
	}
}

func TestTopLevelPermsInherited(t *testing.T) {
	// Top-level id-token: write should reach a job that doesn't specify perms.
	wf := `
on: push
permissions:
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
`
	findings := analyze(t, ".github/workflows/build.yml", wf)
	if !hasRule(findings, RuleOIDC) {
		t.Errorf("top-level id-token: write should be inherited, got: %+v", findings)
	}
}

func TestUntrustedRefMatches(t *testing.T) {
	cases := []struct {
		ref      string
		expected bool
	}{
		{"${{ github.event.pull_request.head.sha }}", true},
		{"${{ github.event.pull_request.head.ref }}", true},
		{"${{ github.head_ref }}", true},
		{"refs/pull/123/merge", true},
		{"refs/pull/${{ github.event.pull_request.number }}/merge", true},
		{"main", false},
		{"${{ github.sha }}", false},
		{"v1.2.3", false},
		{"", false},
	}
	for _, c := range cases {
		got := isUntrustedRef(c.ref)
		if got != c.expected {
			t.Errorf("isUntrustedRef(%q) = %v, want %v", c.ref, got, c.expected)
		}
	}
}

func TestFindingsHaveStableFields(t *testing.T) {
	// Regression guard: ensure category, analyzer name, and rule IDs are
	// stable. Observatory pipelines key on these.
	wf := `
on: pull_request_target
permissions:
  id-token: write
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: x
      - run: npm install
      - run: npm publish
`
	findings := analyze(t, ".github/workflows/regression.yml", wf)
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
		if !strings.HasPrefix(f.RuleID, "GHA_") {
			t.Errorf("finding ruleID %q should have GHA_ prefix", f.RuleID)
		}
		if f.Confidence == 0 {
			t.Errorf("finding %s: confidence should be > 0", f.RuleID)
		}
		if f.Remediation == "" {
			t.Errorf("finding %s: remediation should be non-empty", f.RuleID)
		}
	}
}

// Local-action execution should count as code execution for pwn-request.
func TestLocalActionExecutesCode(t *testing.T) {
	wf := `
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - uses: ./.github/actions/local-thing
`
	findings := analyze(t, ".github/workflows/local.yml", wf)
	if !hasRule(findings, RulePwnRequest) {
		t.Errorf("local action (./...) after PR checkout should trigger PWN_REQUEST, got: %+v", findings)
	}
}

// pull_request_target with PR checkout and a passive grep step should NOT
// trigger PWN_REQUEST (no install/build/test/interpreter call).
func TestSafe_PullRequestTargetCheckoutPassiveGrep(t *testing.T) {
	wf := `
on: pull_request_target
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: grep -r 'TODO' .
`
	findings := analyze(t, ".github/workflows/scan.yml", wf)
	if hasRule(findings, RulePwnRequest) {
		t.Errorf("passive grep step should not trigger PWN_REQUEST, got: %+v", findings)
	}
}
