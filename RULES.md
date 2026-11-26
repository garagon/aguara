# Aguara Rule Catalog

The v0.29.0 catalog contains **259 detections**: **191 built-in pattern rules** defined in 13 YAML files named after the pattern categories, and **68 analyzer-emitted detections** from ci-trust, mcp-capability, kube-policy, pkgmeta, jsrisk, pyrisk, script-risk, skill-policy, skill-chain, rsbuild, npm-policy, pnpm-policy, agent-policy, NLP, toxicflow, and the rug-pull detector. Run `aguara list-rules` for the installed binary's catalog and `aguara explain <RULE_ID>` for a rule's description, scope and remediation.

`K8S_IDENTITY_CAPABILITIES_001` is a LOW `container-security` observation with
`context` impact. It identifies explicit `SETUID`/`SETGID` additions at recognized
Kubernetes container paths, not proven escalation or host access. Privilege
commands remain under SUPPLY_007; MCP_009 broad grants are unchanged. Aliases,
templates and ambiguous structures keep legacy matching rather than receiving
this classification. Disabling the new ID hides the observation without bringing
back a SUPPLY_007 finding for the same declaration. Like every rule, it can be
disabled with `--disable-rule` and changed through `rule_overrides` severity and
`disabled` settings.

MCP_009 uses the `mcp-capability` parser to distinguish broad grants from
capability drops and denies. It reads literal scalar/list values and
`add`/`allow`/`grant` mappings in JSON/YAML, standalone text snippets and
Markdown fenced examples. Explicit privilege requests in prose remain covered.
It does not resolve YAML aliases or merge keys, ambiguous duplicate fields, or
arbitrary configuration fragments embedded in prose. Inputs requiring this
analysis are bounded to 2 MiB and a 100,000-node traversal budget; exceeding a
budget reports an analyzer error, not a clean result. Like every rule, pattern
or analyzer-emitted, MCP_009 accepts `rule_overrides` severity and `disabled`
settings.

Use `aguara list-rules` to list all rules from the CLI, or `aguara explain <RULE_ID>` for details on a specific rule.

Each catalog entry also exposes a `decision_impact`. Most findings are `review`: they independently require a trust decision before execution. `CMDEXEC_013` (ordinary local shell-script execution), `EXTDL_009` (ordinary `pip install`), `EXTDL_011` (ordinary system-package installation), `MCPCFG_004` (a configured remote MCP endpoint), and `K8S_IDENTITY_CAPABILITIES_001` (an explicit capability request) are `context`: they stay visible and can strengthen a nearby chain, but do not restrict the default `aguara audit` agent handoff on their own. Custom rules default to `review`; explicit `--fail-on` gates still apply to both classes.

For writing custom rules, see the [Custom Rules](#custom-rules) section below or the [Contributing Guide](CONTRIBUTING.md).

## Reading the tables

Each table lists every rule in one category of the v0.29.0 catalog (`aguara list-rules --format json`). `Source` is `pattern` for YAML pattern rules and otherwise names the analyzer that emits the rule. Pattern rules come first, then analyzer rules in pipeline order. `Name` is the catalog name; `aguara explain <RULE_ID>` prints the full description.

Rules that target `*.md` also apply to agent instruction files whatever their extension: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, Cursor rules (`.cursor/rules/*.mdc`, `.cursorrules`), Windsurf (`.windsurf/rules/`, `.windsurfrules`), Cline (`.clinerules`), Roo Code (`.roo/rules/`, `.roorules`), Kiro (`.kiro/steering/`), GitHub Copilot (`.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`), Claude Code (`.claude/agents/`, `.claude/commands/`, `.claude/rules/`), Zed (`.rules`), Goose (`.goosehints`), Continue (`.continue/rules/`) and JetBrains (`.aiassistant/rules/`, `.junie/`). File names such as `AGENTS.md` or `CLAUDE.md` are recognised in their documented spelling anywhere in the tree, and in other letter cases only at the scan root or in the tool's config directory (`.claude/`, `.junie/`), so a documentation page such as `docs/agent.md` or `docs/providers/gemini.md` stays documentation. The full list, with the documentation each entry comes from, is in `internal/types/agentfiles.go`. Findings in these files get a higher confidence than the same match in ordinary documentation.

`Severity` is the catalog severity. Some analyzer rules, for example in ci-trust, pkgmeta and jsrisk, report a higher severity when additional evidence is present, and pattern findings inside Markdown fenced code blocks (backtick or tilde fences) of ordinary documentation, such as a README, are reported one level lower. In a `SKILL.md` or an agent instruction file a fenced block is a command the agent is told to run, so it keeps the rule's severity; MCP_009 follows the same contract.

Release history for the supply-chain series: SUPPLY_020 and SUPPLY_021 shipped in v0.8.0; SUPPLY_022 to SUPPLY_025 shipped in v0.15.0 together with the ci-trust, pkgmeta and jsrisk analyzers; SUPPLY_026, emitted by pkgmeta rather than a YAML rule, shipped in v0.23.0.

---

## Prompt Injection (23)

Category `prompt-injection`: 18 pattern rules, 5 analyzer-emitted (`nlp`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| PROMPT_INJECTION_001 | CRITICAL | pattern | Instruction override attempt |
| PROMPT_INJECTION_002 | HIGH | pattern | Role switching attempt |
| PROMPT_INJECTION_003 | HIGH | pattern | Hidden HTML comment with instructions |
| PROMPT_INJECTION_004 | HIGH | pattern | Zero-width character obfuscation |
| PROMPT_INJECTION_005 | MEDIUM | pattern | Urgency and authority manipulation |
| PROMPT_INJECTION_006 | CRITICAL | pattern | Delimiter injection |
| PROMPT_INJECTION_007 | HIGH | pattern | Conversation history poisoning |
| PROMPT_INJECTION_008 | HIGH | pattern | Secrecy instruction |
| PROMPT_INJECTION_009 | HIGH | pattern | Base64-encoded instructions |
| PROMPT_INJECTION_010 | CRITICAL | pattern | Fake system prompt |
| PROMPT_INJECTION_011 | CRITICAL | pattern | Jailbreak template |
| PROMPT_INJECTION_012 | MEDIUM | pattern | Markdown link with deceptive action text |
| PROMPT_INJECTION_013 | MEDIUM | pattern | Instruction in image alt text |
| PROMPT_INJECTION_014 | MEDIUM | pattern | Multi-language injection |
| PROMPT_INJECTION_015 | MEDIUM | pattern | Prompt leaking attempt |
| PROMPT_INJECTION_016 | HIGH | pattern | Self-modifying agent instructions |
| PROMPT_INJECTION_017 | HIGH | pattern | Autonomous agent spawning |
| PROMPT_INJECTION_018 | HIGH | pattern | Runtime events as user-role prompt |
| NLP_AUTHORITY_CLAIM | MEDIUM | nlp | Authority-claim language in untrusted content |
| NLP_CODE_MISMATCH | MEDIUM | nlp | Code block contents diverge from surrounding instructions |
| NLP_HEADING_MISMATCH | MEDIUM | nlp | Section heading does not match the section's instruction content |
| NLP_HIDDEN_INSTRUCTION | HIGH | nlp | Hidden instruction inside non-instructional structure |
| NLP_OVERRIDE_DANGEROUS | CRITICAL | nlp | Instruction override paired with dangerous capability |

## Data Exfiltration (17)

Category `exfiltration`: 16 pattern rules, 1 analyzer-emitted (`nlp`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| EXFIL_001 | HIGH | pattern | Webhook URL for data exfiltration |
| EXFIL_002 | HIGH | pattern | Sensitive file read pattern |
| EXFIL_003 | HIGH | pattern | Data transmission pattern |
| EXFIL_004 | HIGH | pattern | DNS exfiltration pattern |
| EXFIL_005 | HIGH | pattern | curl/wget POST with sensitive data |
| EXFIL_006 | MEDIUM | pattern | Clipboard access with network |
| EXFIL_007 | HIGH | pattern | Environment variable exfiltration |
| EXFIL_008 | HIGH | pattern | File read piped to HTTP transmission |
| EXFIL_009 | MEDIUM | pattern | Base64 encode and send |
| EXFIL_010 | MEDIUM | pattern | Non-standard port communication |
| EXFIL_011 | HIGH | pattern | External context or knowledge sync |
| EXFIL_012 | MEDIUM | pattern | Unrestricted email or messaging access |
| EXFIL_013 | HIGH | pattern | Read sensitive files and transmit externally |
| EXFIL_014 | HIGH | pattern | Environment variable credential in POST data |
| EXFIL_015 | MEDIUM | pattern | Screenshot or screen capture with transmission |
| EXFIL_016 | MEDIUM | pattern | Git history or diff access with transmission |
| NLP_CRED_EXFIL_COMBO | CRITICAL | nlp | Text combines credential access with network transmission |

## Credential Leak (22)

Category `credential-leak`: 22 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| CRED_001 | CRITICAL | pattern | OpenAI API key |
| CRED_002 | CRITICAL | pattern | AWS access key |
| CRED_003 | CRITICAL | pattern | GitHub personal access token |
| CRED_004 | MEDIUM | pattern | Generic API key pattern |
| CRED_005 | CRITICAL | pattern | Private key block |
| CRED_006 | HIGH | pattern | Database connection string |
| CRED_007 | HIGH | pattern | Hardcoded password |
| CRED_008 | HIGH | pattern | Slack or Discord webhook |
| CRED_009 | CRITICAL | pattern | GCP service account key |
| CRED_010 | MEDIUM | pattern | JWT token |
| CRED_011 | HIGH | pattern | Credential in shell export |
| CRED_012 | CRITICAL | pattern | Stripe API key |
| CRED_013 | CRITICAL | pattern | Anthropic API key |
| CRED_014 | HIGH | pattern | SendGrid or Twilio API key |
| CRED_015 | MEDIUM | pattern | CLI credential flags |
| CRED_016 | MEDIUM | pattern | SSH private key in command |
| CRED_017 | LOW | pattern | Docker environment credentials |
| CRED_018 | HIGH | pattern | Credential logging without redaction |
| CRED_019 | HIGH | pattern | Secrets exported to external telemetry |
| CRED_020 | HIGH | pattern | OAuth PKCE verifier exposure |
| CRED_021 | HIGH | pattern | Dotenv file exposure |
| CRED_022 | HIGH | pattern | Hardcoded secret in dotenv format |

## MCP Attack (16)

Category `mcp-attack`: 15 pattern rules, 1 analyzer-emitted (`mcp-capability`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| MCP_001 | CRITICAL | pattern | Tool description injection |
| MCP_002 | HIGH | pattern | Tool name shadowing |
| MCP_003 | HIGH | pattern | Resource URI manipulation |
| MCP_004 | HIGH | pattern | Parameter schema injection |
| MCP_005 | CRITICAL | pattern | Hidden tool registration |
| MCP_006 | HIGH | pattern | Tool output interception |
| MCP_007 | MEDIUM | pattern | Cross-tool data leakage |
| MCP_008 | CRITICAL | pattern | Server manifest tampering |
| MCP_010 | HIGH | pattern | Prompt cache poisoning |
| MCP_011 | HIGH | pattern | Arbitrary MCP server execution |
| MCP_012 | HIGH | pattern | Prototype pollution vector |
| MCP_013 | HIGH | pattern | Approval-execution binding gap |
| MCP_014 | MEDIUM | pattern | Unscoped resource identifier |
| MCP_015 | MEDIUM | pattern | Auth-before-body parsing |
| MCP_016 | HIGH | pattern | Canonicalization bypass |
| MCP_009 | HIGH | mcp-capability | Capability escalation |

## MCP Config (13)

Category `mcp-config`: 13 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| MCPCFG_001 | LOW | pattern | npx MCP server without version pin |
| MCPCFG_002 | HIGH | pattern | Shell metacharacters in MCP config args |
| MCPCFG_003 | LOW | pattern | Hardcoded secrets in MCP env block |
| MCPCFG_004 | LOW | pattern | Non-localhost remote MCP server URL |
| MCPCFG_005 | HIGH | pattern | sudo in MCP server command |
| MCPCFG_006 | HIGH | pattern | Inline code execution in MCP command |
| MCPCFG_007 | HIGH | pattern | Docker privileged or host mount in MCP config |
| MCPCFG_008 | MEDIUM | pattern | Auto-confirm flag bypassing user verification |
| MCPCFG_009 | MEDIUM | pattern | Writable workspace mount |
| MCPCFG_010 | HIGH | pattern | Docker capabilities escalation |
| MCPCFG_011 | MEDIUM | pattern | Unrestricted container network access |
| MCPCFG_012 | HIGH | pattern | uvx MCP server without version pin |
| MCPCFG_013 | MEDIUM | pattern | pip install without hash verification in MCP server setup |

## Supply Chain (63)

Category `supply-chain`: 24 pattern rules, 39 analyzer-emitted (`ci-trust`, `pkgmeta`, `jsrisk`, `pyrisk`, `rsbuild`, `npm-policy`, `pnpm-policy`, `script-risk`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| SUPPLY_001 | HIGH | pattern | Suspicious npm install script |
| SUPPLY_002 | HIGH | pattern | Python setup.py execution |
| SUPPLY_003 | CRITICAL | pattern | Download-and-execute |
| SUPPLY_004 | HIGH | pattern | Makefile hidden commands |
| SUPPLY_005 | HIGH | pattern | Conditional CI execution |
| SUPPLY_006 | HIGH | pattern | Obfuscated shell command |
| SUPPLY_007 | HIGH | pattern | Privilege escalation |
| SUPPLY_008 | CRITICAL | pattern | Reverse shell pattern |
| SUPPLY_009 | HIGH | pattern | Path traversal attempt |
| SUPPLY_010 | MEDIUM | pattern | Symlink attack |
| SUPPLY_011 | HIGH | pattern | Unattended auto-update |
| SUPPLY_012 | MEDIUM | pattern | Git clone and execute chain |
| SUPPLY_013 | MEDIUM | pattern | Unpinned GitHub Actions |
| SUPPLY_014 | MEDIUM | pattern | Package install from arbitrary URL |
| SUPPLY_015 | HIGH | pattern | Container bind mount to sensitive host path |
| SUPPLY_016 | MEDIUM | pattern | Workspace boundary escape |
| SUPPLY_017 | HIGH | pattern | Hardlink workspace escape |
| SUPPLY_018 | CRITICAL | pattern | Sandbox escape via process spawn |
| SUPPLY_019 | MEDIUM | pattern | Stale PID lock exploitation |
| SUPPLY_020 | HIGH | pattern | GitHub Actions untrusted input injection |
| SUPPLY_021 | MEDIUM | pattern | GitHub Actions overly broad permissions |
| SUPPLY_022 | HIGH | pattern | GitHub Actions OIDC token request variables in executable code |
| SUPPLY_023 | CRITICAL | pattern | GitHub Actions runner process memory access |
| SUPPLY_025 | HIGH | pattern | Claude Code workspace persistence path |
| GHA_CACHE_001 | HIGH | ci-trust | Untrusted PR workflow can write cache consumed by privileged workflows |
| GHA_CHECKOUT_001 | HIGH | ci-trust | Privileged workflow checks out PR code with persisted credentials |
| GHA_OIDC_001 | HIGH | ci-trust | OIDC token available in a job that executes install/build/test code |
| GHA_PWN_REQUEST_001 | HIGH | ci-trust | pull_request_target executes untrusted PR code |
| NPM_GIT_INSTALL_TRUST_001 | INFO | pkgmeta | npm v12 readiness: git dependency needs install trust |
| NPM_LIFECYCLE_GIT_001 | HIGH | pkgmeta | Git dependency can execute lifecycle code during install |
| NPM_OPTIONAL_GIT_001 | MEDIUM | pkgmeta | Optional dependency resolves executable code from git |
| NPM_PUBLISH_SURFACE_001 | HIGH | pkgmeta | Package publish surface exposed to install-time code |
| NPM_REMOTE_INSTALL_TRUST_001 | INFO | pkgmeta | npm v12 readiness: remote tarball needs install trust |
| SUPPLY_026 | HIGH | pkgmeta | npm lifecycle script executes local JavaScript |
| AGENT_PERSISTENCE_001 | HIGH | jsrisk | Persistence through Claude Code or VS Code workspace automation |
| JS_BUN_SECOND_STAGE_001 | HIGH | jsrisk | Bun second-stage execution |
| JS_CI_SECRET_HARVEST_001 | CRITICAL | jsrisk | CI credential harvesting with network or registry sink |
| JS_DAEMON_001 | HIGH | jsrisk | Detached background execution from JavaScript |
| JS_DNS_TXT_EXFIL_001 | HIGH | jsrisk | DNS TXT exfiltration chain in JavaScript |
| JS_GITHUB_C2_001 | HIGH | jsrisk | GitHub used as payload or command channel |
| JS_HOST_TRUST_TAMPER_001 | HIGH | jsrisk | Host trust surface tampering |
| JS_OBF_001 | MEDIUM | jsrisk | Large obfuscated JavaScript payload |
| JS_PROC_MEM_OIDC_001 | CRITICAL | jsrisk | Runner process memory access combined with OIDC token reference |
| JS_SUDOERS_TAMPER_001 | HIGH | jsrisk | Sudoers privilege tampering |
| JS_WIPER_TRIPWIRE_001 | HIGH | jsrisk | Destructive wipe of sensitive paths |
| PY_IMPORTTIME_REMOTE_JS_001 | CRITICAL | pyrisk | PyPI import-time remote JavaScript execution |
| RS_BUILD_WALLET_EXFIL_001 | CRITICAL | rsbuild | Rust build.rs wallet/keystore exfiltration |
| NPM_ALLOW_GIT_RELAXED_001 | MEDIUM | npm-policy | npm git-dependency resolution pinned open |
| NPM_ALLOW_REMOTE_RELAXED_001 | MEDIUM | npm-policy | npm remote-tarball resolution pinned open |
| NPM_ALLOW_SCRIPTS_UNPINNED_001 | MEDIUM | npm-policy | npm allowScripts approval not version-pinned |
| NPM_DANGEROUS_ALL_SCRIPTS_001 | HIGH | npm-policy | npm dangerously-allow-all-scripts enabled |
| PNPM_BUILD_APPROVAL_PENDING_001 | MEDIUM | pnpm-policy | pnpm allowBuilds entry pending decision |
| PNPM_DANGEROUS_BUILDS_001 | HIGH | pnpm-policy | pnpm dangerouslyAllowAllBuilds enabled |
| PNPM_EXOTIC_SUBDEPS_DISABLED_001 | MEDIUM | pnpm-policy | pnpm blockExoticSubdeps disabled |
| PNPM_LEGACY_BUILD_POLICY_001 | INFO | pnpm-policy | pnpm legacy v10 build-policy setting |
| PNPM_MIN_RELEASE_AGE_DISABLED_001 | LOW | pnpm-policy | pnpm minimumReleaseAge disabled |
| PNPM_MIN_RELEASE_AGE_NON_STRICT_001 | LOW | pnpm-policy | pnpm minimumReleaseAge not strictly enforced |
| PNPM_STRICT_DEP_BUILDS_DISABLED_001 | MEDIUM | pnpm-policy | pnpm strictDepBuilds disabled |
| PNPM_TRUST_LOCKFILE_001 | MEDIUM | pnpm-policy | pnpm trustLockfile enabled |
| PNPM_TRUST_POLICY_OFF_001 | LOW | pnpm-policy | pnpm trustPolicy explicitly off |
| PY_WORLD_WRITABLE_001 | MEDIUM | script-risk | Python code applies world-writable permissions |
| SHELL_UNSAFE_NPM_SOURCE_001 | MEDIUM | script-risk | Unencrypted npm dependency source in a script |
| SHELL_UNSAFE_PIP_SOURCE_001 | MEDIUM | script-risk | Unencrypted pip dependency source in a script |

## Supply Chain Exfil (14)

Category `supply-chain-exfil`: 10 pattern rules, 4 analyzer-emitted (`script-risk`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| SC-EX-001 | CRITICAL | pattern | Credential file read in Python code |
| SC-EX-002 | CRITICAL | pattern | File content encoding for exfiltration |
| SC-EX-003 | CRITICAL | pattern | Environment variable bulk collection with network send |
| SC-EX-004 | CRITICAL | pattern | .pth file with executable content |
| SC-EX-005 | HIGH | pattern | Cloud metadata endpoint access in Python |
| SC-EX-006 | CRITICAL | pattern | Kubernetes secrets API access outside K8s libraries |
| SC-EX-008 | HIGH | pattern | Hardcoded cryptographic key material |
| SC-EX-009 | CRITICAL | pattern | Archive creation combined with HTTP POST |
| SC-EX-010 | MEDIUM | pattern | .pth file presence with non-path content |
| SUPPLY_024 | HIGH | pattern | Session-Network exfil endpoint |
| PY_CONTEXT_EXFIL_001 | HIGH | script-risk | Sensitive local context paired with network transmission |
| PY_DECODE_EXEC_001 | CRITICAL | script-risk | Obfuscated Python payload execution |
| PY_REMOTE_FETCH_EXEC_001 | CRITICAL | script-risk | Remote Python payload execution |
| SC-EX-007 | CRITICAL | script-risk | Systemd or cron persistence installation |

## External Download (16)

Category `external-download`: 16 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| EXTDL_001 | HIGH | pattern | Runtime URL controls agent behavior |
| EXTDL_002 | MEDIUM | pattern | Remote SDK or script fetch as agent input |
| EXTDL_003 | LOW | pattern | npx auto-install without confirmation |
| EXTDL_004 | LOW | pattern | Global package installation |
| EXTDL_005 | MEDIUM | pattern | Shell profile modification for persistence |
| EXTDL_006 | HIGH | pattern | MCP server auto-registration |
| EXTDL_007 | CRITICAL | pattern | Binary download and execute |
| EXTDL_008 | LOW | pattern | Unverified npx package execution |
| EXTDL_009 | LOW | pattern | pip install arbitrary package |
| EXTDL_010 | LOW | pattern | go install from remote |
| EXTDL_011 | LOW | pattern | System package manager install |
| EXTDL_012 | LOW | pattern | Cargo or gem install from remote |
| EXTDL_013 | CRITICAL | pattern | Curl or wget piped to shell |
| EXTDL_014 | MEDIUM | pattern | Conditional download and install |
| EXTDL_015 | MEDIUM | pattern | Docker pull and run untrusted image |
| EXTDL_016 | MEDIUM | pattern | Download binary or archive from URL |

## Command Execution (16)

Category `command-execution`: 16 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| CMDEXEC_001 | MEDIUM | pattern | Shell subprocess with shell=True |
| CMDEXEC_002 | MEDIUM | pattern | Dynamic code evaluation |
| CMDEXEC_003 | MEDIUM | pattern | Python subprocess execution |
| CMDEXEC_004 | HIGH | pattern | Node.js child process execution |
| CMDEXEC_005 | HIGH | pattern | Shell command with dangerous payload |
| CMDEXEC_006 | HIGH | pattern | Java/Go command execution API |
| CMDEXEC_007 | HIGH | pattern | PowerShell command execution |
| CMDEXEC_008 | MEDIUM | pattern | Terminal multiplexer command injection |
| CMDEXEC_009 | MEDIUM | pattern | Agent shell tool usage |
| CMDEXEC_010 | MEDIUM | pattern | MCP code execution tool |
| CMDEXEC_011 | MEDIUM | pattern | Cron or scheduled command execution |
| CMDEXEC_012 | LOW | pattern | Chained shell command execution |
| CMDEXEC_013 | LOW | pattern | Shell script file execution |
| CMDEXEC_014 | HIGH | pattern | Hex or octal escape obfuscation |
| CMDEXEC_015 | HIGH | pattern | Process substitution or eval-download execution |
| INDIRECT_010 | LOW | pattern | Unscoped Bash tool in allowed tools |

## Indirect Injection (10)

Category `indirect-injection`: 10 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| INDIRECT_001 | HIGH | pattern | Fetch URL and use as instructions |
| INDIRECT_003 | HIGH | pattern | Read external content and apply as rules |
| INDIRECT_004 | HIGH | pattern | Remote config controlling agent behavior |
| INDIRECT_005 | LOW | pattern | User-provided URL consumed by agent |
| INDIRECT_008 | HIGH | pattern | Email or message content as instructions |
| INDIRECT_009 | MEDIUM | pattern | External API response drives agent behavior |
| INDIRECT_011 | HIGH | pattern | Database or cache query driving agent behavior |
| INDIRECT_012 | HIGH | pattern | Webhook or callback registration with external service |
| INDIRECT_013 | HIGH | pattern | Git clone and execute fetched code |
| INDIRECT_014 | MEDIUM | pattern | Environment variable injection from external source |

## Third-Party Content (10)

Category `third-party-content`: 10 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| THIRDPARTY_001 | LOW | pattern | Runtime URL controlling behavior |
| THIRDPARTY_002 | LOW | pattern | Mutable GitHub raw content reference |
| THIRDPARTY_003 | HIGH | pattern | JavaScript eval or Function with external data |
| THIRDPARTY_004 | LOW | pattern | External API response used without validation |
| THIRDPARTY_005 | HIGH | pattern | Remote template or prompt loaded at runtime |
| THIRDPARTY_006 | HIGH | pattern | Unescaped user input in HTML output |
| THIRDPARTY_007 | HIGH | pattern | Unsafe deserialization from untrusted source |
| THIRDPARTY_008 | MEDIUM | pattern | Script or asset loaded without integrity check |
| THIRDPARTY_009 | MEDIUM | pattern | HTTP downgrade from HTTPS |
| THIRDPARTY_010 | HIGH | pattern | Unsigned plugin or extension loading |

## SSRF & Cloud (11)

Category `ssrf-cloud`: 11 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| SSRF_001 | CRITICAL | pattern | Cloud metadata URL |
| SSRF_002 | HIGH | pattern | Internal IP range access |
| SSRF_003 | HIGH | pattern | Kubernetes service discovery |
| SSRF_004 | CRITICAL | pattern | AWS IMDS token request |
| SSRF_005 | HIGH | pattern | Docker socket access |
| SSRF_006 | HIGH | pattern | Localhost bypass |
| SSRF_007 | CRITICAL | pattern | Cloud credential endpoint |
| SSRF_008 | MEDIUM | pattern | DNS rebinding setup |
| SSRF_009 | HIGH | pattern | IPv4 alternative numeric encoding |
| SSRF_010 | HIGH | pattern | IPv6 transition address with embedded IPv4 |
| SSRF_011 | HIGH | pattern | IPv6 multicast SSRF bypass |

## Unicode Attack (10)

Category `unicode-attack`: 10 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| UNI_001 | HIGH | pattern | Right-to-left override |
| UNI_002 | HIGH | pattern | Bidi text manipulation |
| UNI_003 | MEDIUM | pattern | Homoglyph domain spoofing |
| UNI_004 | MEDIUM | pattern | Invisible separator injection |
| UNI_005 | MEDIUM | pattern | Combining character obfuscation |
| UNI_006 | HIGH | pattern | Tag characters for hidden data |
| UNI_007 | MEDIUM | pattern | Punycode domains |
| UNI_008 | MEDIUM | pattern | Zero-width character sequences |
| UNI_009 | MEDIUM | pattern | Unicode normalization inconsistency |
| UNI_010 | MEDIUM | pattern | Mixed-script confusable in identifiers |

## Toxic Flow (6)

Category `toxic-flow`: 6 analyzer-emitted (`toxicflow`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| TOXIC_001 | HIGH | toxicflow | Private data read with public output |
| TOXIC_002 | HIGH | toxicflow | Private data read with code execution |
| TOXIC_003 | HIGH | toxicflow | Destructive actions with code execution |
| TOXIC_CROSS_001 | HIGH | toxicflow | Cross-file credential exfiltration across MCP tools |
| TOXIC_CROSS_002 | HIGH | toxicflow | Cross-file env-to-exec chain across MCP tools |
| TOXIC_CROSS_003 | HIGH | toxicflow | Cross-file destructive + exec combo across MCP tools |

## Agent Trust (10)

Category `agent-trust`: 10 analyzer-emitted (`agent-policy`, `skill-policy`, `skill-chain`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| AGENTCFG_BROAD_ALLOW_001 | MEDIUM | agent-policy | Claude Code permissions pre-approve dangerous commands |
| AGENTCFG_BYPASS_PERMS_001 | HIGH | agent-policy | Claude Code permissions default to bypass |
| AGENTCFG_ENV_EXEC_001 | HIGH | agent-policy | Claude Code settings inject a code-execution environment variable |
| AGENTCFG_HELPER_REPO_SCRIPT_001 | MEDIUM | agent-policy | Claude Code credential helper runs a repo-shipped script |
| AGENTCFG_HOOK_FETCH_EXEC_001 | CRITICAL | agent-policy | Claude Code hook downloads and executes remote code |
| AGENTCFG_MCP_AUTOAPPROVE_001 | MEDIUM | agent-policy | Claude Code auto-approves all project MCP servers |
| AGENTCFG_PERMS_WEAK_MODE_001 | LOW | agent-policy | Claude Code permissions default to an auto-approving mode |
| AGENTCFG_SECRET_READ_ALLOW_001 | MEDIUM | agent-policy | Claude Code permissions pre-approve reading secrets |
| AGENT_SKILL_WILDCARD_TOOLS_001 | MEDIUM | skill-policy | Skill pre-approves every tool |
| AGENT_FORCED_HELPER_RISK_001 | HIGH | skill-chain | Mandatory skill helper contains hidden high-risk behavior |

## Container Security (1)

Category `container-security`: 1 analyzer-emitted (`kube-policy`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| K8S_IDENTITY_CAPABILITIES_001 | LOW | kube-policy | Kubernetes workload requests identity-changing capabilities |

## Rug Pull (1)

Category `rug-pull`: 1 analyzer-emitted (`rugpull`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| RUGPULL_001 | CRITICAL | rugpull | Tool description changed with dangerous content |

---

## Custom Rules

You can extend Aguara with your own rules in YAML:

```yaml
id: CUSTOM_001
name: "Internal API endpoint"
description: "Detects references to internal APIs"
severity: HIGH
category: custom
targets: ["*.md", "*.txt"]
match_mode: any
patterns:
  - type: regex
    value: "https?://internal\\.mycompany\\.com"
  - type: contains
    value: "api.internal"
exclude_patterns:
  - type: regex
    value: "^\\s*#"
examples:
  true_positive:
    - "Fetch data from https://internal.mycompany.com/api/users"
    - "# load users\nFetch data from https://internal.mycompany.com/api/users"
  false_positive:
    - "Our public API is at https://api.mycompany.com"
    - "# https://internal.mycompany.com is the old host"
```

`exclude_patterns` entries suppress a match when they match the line or lines the match spans (`scope: line`, the default). Add `scope: context` to an entry only when it identifies a documentation section, such as an `## Installation` heading; a context-scoped exclude also checks the 3 lines before the match. With `match_mode: all`, a rule fires when every pattern matches somewhere in the file; add `within_lines: N` to require all of them inside N consecutive lines. Built-in rules that describe an action chain, such as reading a secret and then sending it, use 25 so that numbered steps, a heredoc or a multi-line manifest between the two halves still match; CRED_019, CRED_021, THIRDPARTY_001 and THIRDPARTY_004, whose second pattern is a single common word, use 5. Examples may span several lines and are checked with the same matcher a scan uses.

Load custom rules with the `--rules` flag:

```bash
aguara scan .claude/skills/ --rules ./my-rules/
```

Repeat `--rules` to load several directories (`--rules ./team-rules/ --rules ./my-rules/`).
The directory may be a symbolic link. Inside it, symlinked rule files are read
from their target; symlinked subdirectories are not followed and are reported
as a configuration problem.

A rule file must be a regular file of at most 1 MB, whatever its reported
size; a `.yaml` or `.yml` entry that is a named pipe, socket or device, or a
link to one, is a configuration problem and is not read. In the development
version, loading a directory stops with a configuration problem after 100,000
files and directories, 10,000 rule files or 128 MiB of rule files, and rule
files more than 32 directories below it are not loaded.

See the [Contributing Guide](CONTRIBUTING.md) for more details on rule structure and testing.
