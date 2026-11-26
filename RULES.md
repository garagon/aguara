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

Each table lists every rule in one category of the v0.29.0 catalog (`aguara list-rules --format json`). Each rule ID carries an anchor named after the ID in lower case (for example `RULES.md#cred_002`); SARIF `helpUri` links to it. `Source` is `pattern` for YAML pattern rules and otherwise names the analyzer that emits the rule. Pattern rules come first, then analyzer rules in pipeline order. `Name` is the catalog name; `aguara explain <RULE_ID>` prints the full description.

Rules that target `*.md` also apply to agent instruction files whatever their extension: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, Cursor rules (`.cursor/rules/*.mdc`, `.cursorrules`), Windsurf (`.windsurf/rules/`, `.windsurfrules`), Cline (`.clinerules`), Roo Code (`.roo/rules/`, `.roorules`), Kiro (`.kiro/steering/`), GitHub Copilot (`.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`), Claude Code (`.claude/agents/`, `.claude/commands/`, `.claude/rules/`), Zed (`.rules`), Goose (`.goosehints`), Continue (`.continue/rules/`) and JetBrains (`.aiassistant/rules/`, `.junie/`). File names such as `AGENTS.md` or `CLAUDE.md` are recognised in their documented spelling anywhere in the tree, and in other letter cases only at the scan root or in the tool's config directory (`.claude/`, `.junie/`), so a documentation page such as `docs/agent.md` or `docs/providers/gemini.md` stays documentation. The full list, with the documentation each entry comes from, is in `internal/types/agentfiles.go`. Findings in these files get a higher confidence than the same match in ordinary documentation.

`Severity` is the catalog severity. Some analyzer rules, for example in ci-trust, pkgmeta and jsrisk, report a higher severity when additional evidence is present, and pattern findings inside Markdown fenced code blocks (backtick or tilde fences) of ordinary documentation, such as a README, are reported one level lower. In a `SKILL.md` or an agent instruction file a fenced block is a command the agent is told to run, so it keeps the rule's severity; MCP_009 follows the same contract.

Release history for the supply-chain series: SUPPLY_020 and SUPPLY_021 shipped in v0.8.0; SUPPLY_022 to SUPPLY_025 shipped in v0.15.0 together with the ci-trust, pkgmeta and jsrisk analyzers; SUPPLY_026, emitted by pkgmeta rather than a YAML rule, shipped in v0.23.0.

---

## Prompt Injection (23)

Category `prompt-injection`: 18 pattern rules, 5 analyzer-emitted (`nlp`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="prompt_injection_001"></a>PROMPT_INJECTION_001 | CRITICAL | pattern | Instruction override attempt |
| <a id="prompt_injection_002"></a>PROMPT_INJECTION_002 | HIGH | pattern | Role switching attempt |
| <a id="prompt_injection_003"></a>PROMPT_INJECTION_003 | HIGH | pattern | Hidden HTML comment with instructions |
| <a id="prompt_injection_004"></a>PROMPT_INJECTION_004 | HIGH | pattern | Zero-width character obfuscation |
| <a id="prompt_injection_005"></a>PROMPT_INJECTION_005 | MEDIUM | pattern | Urgency and authority manipulation |
| <a id="prompt_injection_006"></a>PROMPT_INJECTION_006 | CRITICAL | pattern | Delimiter injection |
| <a id="prompt_injection_007"></a>PROMPT_INJECTION_007 | HIGH | pattern | Conversation history poisoning |
| <a id="prompt_injection_008"></a>PROMPT_INJECTION_008 | HIGH | pattern | Secrecy instruction |
| <a id="prompt_injection_009"></a>PROMPT_INJECTION_009 | HIGH | pattern | Base64-encoded instructions |
| <a id="prompt_injection_010"></a>PROMPT_INJECTION_010 | CRITICAL | pattern | Fake system prompt |
| <a id="prompt_injection_011"></a>PROMPT_INJECTION_011 | CRITICAL | pattern | Jailbreak template |
| <a id="prompt_injection_012"></a>PROMPT_INJECTION_012 | MEDIUM | pattern | Markdown link with deceptive action text |
| <a id="prompt_injection_013"></a>PROMPT_INJECTION_013 | MEDIUM | pattern | Instruction in image alt text |
| <a id="prompt_injection_014"></a>PROMPT_INJECTION_014 | MEDIUM | pattern | Multi-language injection |
| <a id="prompt_injection_015"></a>PROMPT_INJECTION_015 | MEDIUM | pattern | Prompt leaking attempt |
| <a id="prompt_injection_016"></a>PROMPT_INJECTION_016 | HIGH | pattern | Self-modifying agent instructions |
| <a id="prompt_injection_017"></a>PROMPT_INJECTION_017 | HIGH | pattern | Autonomous agent spawning |
| <a id="prompt_injection_018"></a>PROMPT_INJECTION_018 | HIGH | pattern | Runtime events as user-role prompt |
| <a id="nlp_authority_claim"></a>NLP_AUTHORITY_CLAIM | MEDIUM | nlp | Authority-claim language in untrusted content |
| <a id="nlp_code_mismatch"></a>NLP_CODE_MISMATCH | MEDIUM | nlp | Code block contents diverge from surrounding instructions |
| <a id="nlp_heading_mismatch"></a>NLP_HEADING_MISMATCH | MEDIUM | nlp | Section heading does not match the section's instruction content |
| <a id="nlp_hidden_instruction"></a>NLP_HIDDEN_INSTRUCTION | HIGH | nlp | Hidden instruction inside non-instructional structure |
| <a id="nlp_override_dangerous"></a>NLP_OVERRIDE_DANGEROUS | CRITICAL | nlp | Instruction override paired with dangerous capability |

## Data Exfiltration (17)

Category `exfiltration`: 16 pattern rules, 1 analyzer-emitted (`nlp`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="exfil_001"></a>EXFIL_001 | HIGH | pattern | Webhook URL for data exfiltration |
| <a id="exfil_002"></a>EXFIL_002 | HIGH | pattern | Sensitive file read pattern |
| <a id="exfil_003"></a>EXFIL_003 | HIGH | pattern | Data transmission pattern |
| <a id="exfil_004"></a>EXFIL_004 | HIGH | pattern | DNS exfiltration pattern |
| <a id="exfil_005"></a>EXFIL_005 | HIGH | pattern | curl/wget POST with sensitive data |
| <a id="exfil_006"></a>EXFIL_006 | MEDIUM | pattern | Clipboard access with network |
| <a id="exfil_007"></a>EXFIL_007 | HIGH | pattern | Environment variable exfiltration |
| <a id="exfil_008"></a>EXFIL_008 | HIGH | pattern | File read piped to HTTP transmission |
| <a id="exfil_009"></a>EXFIL_009 | MEDIUM | pattern | Base64 encode and send |
| <a id="exfil_010"></a>EXFIL_010 | MEDIUM | pattern | Non-standard port communication |
| <a id="exfil_011"></a>EXFIL_011 | HIGH | pattern | External context or knowledge sync |
| <a id="exfil_012"></a>EXFIL_012 | MEDIUM | pattern | Unrestricted email or messaging access |
| <a id="exfil_013"></a>EXFIL_013 | HIGH | pattern | Read sensitive files and transmit externally |
| <a id="exfil_014"></a>EXFIL_014 | HIGH | pattern | Environment variable credential in POST data |
| <a id="exfil_015"></a>EXFIL_015 | MEDIUM | pattern | Screenshot or screen capture with transmission |
| <a id="exfil_016"></a>EXFIL_016 | MEDIUM | pattern | Git history or diff access with transmission |
| <a id="nlp_cred_exfil_combo"></a>NLP_CRED_EXFIL_COMBO | CRITICAL | nlp | Text combines credential access with network transmission |

## Credential Leak (22)

Category `credential-leak`: 22 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="cred_001"></a>CRED_001 | CRITICAL | pattern | OpenAI API key |
| <a id="cred_002"></a>CRED_002 | CRITICAL | pattern | AWS access key |
| <a id="cred_003"></a>CRED_003 | CRITICAL | pattern | GitHub personal access token |
| <a id="cred_004"></a>CRED_004 | MEDIUM | pattern | Generic API key pattern |
| <a id="cred_005"></a>CRED_005 | CRITICAL | pattern | Private key block |
| <a id="cred_006"></a>CRED_006 | HIGH | pattern | Database connection string |
| <a id="cred_007"></a>CRED_007 | HIGH | pattern | Hardcoded password |
| <a id="cred_008"></a>CRED_008 | HIGH | pattern | Slack or Discord webhook |
| <a id="cred_009"></a>CRED_009 | CRITICAL | pattern | GCP service account key |
| <a id="cred_010"></a>CRED_010 | MEDIUM | pattern | JWT token |
| <a id="cred_011"></a>CRED_011 | HIGH | pattern | Credential in shell export |
| <a id="cred_012"></a>CRED_012 | CRITICAL | pattern | Stripe API key |
| <a id="cred_013"></a>CRED_013 | CRITICAL | pattern | Anthropic API key |
| <a id="cred_014"></a>CRED_014 | HIGH | pattern | SendGrid or Twilio API key |
| <a id="cred_015"></a>CRED_015 | MEDIUM | pattern | CLI credential flags |
| <a id="cred_016"></a>CRED_016 | MEDIUM | pattern | SSH private key in command |
| <a id="cred_017"></a>CRED_017 | LOW | pattern | Docker environment credentials |
| <a id="cred_018"></a>CRED_018 | HIGH | pattern | Credential logging without redaction |
| <a id="cred_019"></a>CRED_019 | HIGH | pattern | Secrets exported to external telemetry |
| <a id="cred_020"></a>CRED_020 | HIGH | pattern | OAuth PKCE verifier exposure |
| <a id="cred_021"></a>CRED_021 | HIGH | pattern | Dotenv file exposure |
| <a id="cred_022"></a>CRED_022 | HIGH | pattern | Hardcoded secret in dotenv format |

## MCP Attack (16)

Category `mcp-attack`: 15 pattern rules, 1 analyzer-emitted (`mcp-capability`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="mcp_001"></a>MCP_001 | CRITICAL | pattern | Tool description injection |
| <a id="mcp_002"></a>MCP_002 | HIGH | pattern | Tool name shadowing |
| <a id="mcp_003"></a>MCP_003 | HIGH | pattern | Resource URI manipulation |
| <a id="mcp_004"></a>MCP_004 | HIGH | pattern | Parameter schema injection |
| <a id="mcp_005"></a>MCP_005 | CRITICAL | pattern | Hidden tool registration |
| <a id="mcp_006"></a>MCP_006 | HIGH | pattern | Tool output interception |
| <a id="mcp_007"></a>MCP_007 | MEDIUM | pattern | Cross-tool data leakage |
| <a id="mcp_008"></a>MCP_008 | CRITICAL | pattern | Server manifest tampering |
| <a id="mcp_010"></a>MCP_010 | HIGH | pattern | Prompt cache poisoning |
| <a id="mcp_011"></a>MCP_011 | HIGH | pattern | Arbitrary MCP server execution |
| <a id="mcp_012"></a>MCP_012 | HIGH | pattern | Prototype pollution vector |
| <a id="mcp_013"></a>MCP_013 | HIGH | pattern | Approval-execution binding gap |
| <a id="mcp_014"></a>MCP_014 | MEDIUM | pattern | Unscoped resource identifier |
| <a id="mcp_015"></a>MCP_015 | MEDIUM | pattern | Auth-before-body parsing |
| <a id="mcp_016"></a>MCP_016 | HIGH | pattern | Canonicalization bypass |
| <a id="mcp_009"></a>MCP_009 | HIGH | mcp-capability | Capability escalation |

## MCP Config (13)

Category `mcp-config`: 13 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="mcpcfg_001"></a>MCPCFG_001 | LOW | pattern | npx MCP server without version pin |
| <a id="mcpcfg_002"></a>MCPCFG_002 | HIGH | pattern | Shell metacharacters in MCP config args |
| <a id="mcpcfg_003"></a>MCPCFG_003 | LOW | pattern | Hardcoded secrets in MCP env block |
| <a id="mcpcfg_004"></a>MCPCFG_004 | LOW | pattern | Non-localhost remote MCP server URL |
| <a id="mcpcfg_005"></a>MCPCFG_005 | HIGH | pattern | sudo in MCP server command |
| <a id="mcpcfg_006"></a>MCPCFG_006 | HIGH | pattern | Inline code execution in MCP command |
| <a id="mcpcfg_007"></a>MCPCFG_007 | HIGH | pattern | Docker privileged or host mount in MCP config |
| <a id="mcpcfg_008"></a>MCPCFG_008 | MEDIUM | pattern | Auto-confirm flag bypassing user verification |
| <a id="mcpcfg_009"></a>MCPCFG_009 | MEDIUM | pattern | Writable workspace mount |
| <a id="mcpcfg_010"></a>MCPCFG_010 | HIGH | pattern | Docker capabilities escalation |
| <a id="mcpcfg_011"></a>MCPCFG_011 | MEDIUM | pattern | Unrestricted container network access |
| <a id="mcpcfg_012"></a>MCPCFG_012 | HIGH | pattern | uvx MCP server without version pin |
| <a id="mcpcfg_013"></a>MCPCFG_013 | MEDIUM | pattern | pip install without hash verification in MCP server setup |

## Supply Chain (63)

Category `supply-chain`: 24 pattern rules, 39 analyzer-emitted (`ci-trust`, `pkgmeta`, `jsrisk`, `pyrisk`, `rsbuild`, `npm-policy`, `pnpm-policy`, `script-risk`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="supply_001"></a>SUPPLY_001 | HIGH | pattern | Suspicious npm install script |
| <a id="supply_002"></a>SUPPLY_002 | HIGH | pattern | Python setup.py execution |
| <a id="supply_003"></a>SUPPLY_003 | CRITICAL | pattern | Download-and-execute |
| <a id="supply_004"></a>SUPPLY_004 | HIGH | pattern | Makefile hidden commands |
| <a id="supply_005"></a>SUPPLY_005 | HIGH | pattern | Conditional CI execution |
| <a id="supply_006"></a>SUPPLY_006 | HIGH | pattern | Obfuscated shell command |
| <a id="supply_007"></a>SUPPLY_007 | HIGH | pattern | Privilege escalation |
| <a id="supply_008"></a>SUPPLY_008 | CRITICAL | pattern | Reverse shell pattern |
| <a id="supply_009"></a>SUPPLY_009 | HIGH | pattern | Path traversal attempt |
| <a id="supply_010"></a>SUPPLY_010 | MEDIUM | pattern | Symlink attack |
| <a id="supply_011"></a>SUPPLY_011 | HIGH | pattern | Unattended auto-update |
| <a id="supply_012"></a>SUPPLY_012 | MEDIUM | pattern | Git clone and execute chain |
| <a id="supply_013"></a>SUPPLY_013 | MEDIUM | pattern | Unpinned GitHub Actions |
| <a id="supply_014"></a>SUPPLY_014 | MEDIUM | pattern | Package install from arbitrary URL |
| <a id="supply_015"></a>SUPPLY_015 | HIGH | pattern | Container bind mount to sensitive host path |
| <a id="supply_016"></a>SUPPLY_016 | MEDIUM | pattern | Workspace boundary escape |
| <a id="supply_017"></a>SUPPLY_017 | HIGH | pattern | Hardlink workspace escape |
| <a id="supply_018"></a>SUPPLY_018 | CRITICAL | pattern | Sandbox escape via process spawn |
| <a id="supply_019"></a>SUPPLY_019 | MEDIUM | pattern | Stale PID lock exploitation |
| <a id="supply_020"></a>SUPPLY_020 | HIGH | pattern | GitHub Actions untrusted input injection |
| <a id="supply_021"></a>SUPPLY_021 | MEDIUM | pattern | GitHub Actions overly broad permissions |
| <a id="supply_022"></a>SUPPLY_022 | HIGH | pattern | GitHub Actions OIDC token request variables in executable code |
| <a id="supply_023"></a>SUPPLY_023 | CRITICAL | pattern | GitHub Actions runner process memory access |
| <a id="supply_025"></a>SUPPLY_025 | HIGH | pattern | Claude Code workspace persistence path |
| <a id="gha_cache_001"></a>GHA_CACHE_001 | HIGH | ci-trust | Untrusted PR workflow can write cache consumed by privileged workflows |
| <a id="gha_checkout_001"></a>GHA_CHECKOUT_001 | HIGH | ci-trust | Privileged workflow checks out PR code with persisted credentials |
| <a id="gha_oidc_001"></a>GHA_OIDC_001 | HIGH | ci-trust | OIDC token available in a job that executes install/build/test code |
| <a id="gha_pwn_request_001"></a>GHA_PWN_REQUEST_001 | HIGH | ci-trust | pull_request_target executes untrusted PR code |
| <a id="npm_git_install_trust_001"></a>NPM_GIT_INSTALL_TRUST_001 | INFO | pkgmeta | npm v12 readiness: git dependency needs install trust |
| <a id="npm_lifecycle_git_001"></a>NPM_LIFECYCLE_GIT_001 | HIGH | pkgmeta | Git dependency can execute lifecycle code during install |
| <a id="npm_optional_git_001"></a>NPM_OPTIONAL_GIT_001 | MEDIUM | pkgmeta | Optional dependency resolves executable code from git |
| <a id="npm_publish_surface_001"></a>NPM_PUBLISH_SURFACE_001 | HIGH | pkgmeta | Package publish surface exposed to install-time code |
| <a id="npm_remote_install_trust_001"></a>NPM_REMOTE_INSTALL_TRUST_001 | INFO | pkgmeta | npm v12 readiness: remote tarball needs install trust |
| <a id="supply_026"></a>SUPPLY_026 | HIGH | pkgmeta | npm lifecycle script executes local JavaScript |
| <a id="agent_persistence_001"></a>AGENT_PERSISTENCE_001 | HIGH | jsrisk | Persistence through Claude Code or VS Code workspace automation |
| <a id="js_bun_second_stage_001"></a>JS_BUN_SECOND_STAGE_001 | HIGH | jsrisk | Bun second-stage execution |
| <a id="js_ci_secret_harvest_001"></a>JS_CI_SECRET_HARVEST_001 | CRITICAL | jsrisk | CI credential harvesting with network or registry sink |
| <a id="js_daemon_001"></a>JS_DAEMON_001 | HIGH | jsrisk | Detached background execution from JavaScript |
| <a id="js_dns_txt_exfil_001"></a>JS_DNS_TXT_EXFIL_001 | HIGH | jsrisk | DNS TXT exfiltration chain in JavaScript |
| <a id="js_github_c2_001"></a>JS_GITHUB_C2_001 | HIGH | jsrisk | GitHub used as payload or command channel |
| <a id="js_host_trust_tamper_001"></a>JS_HOST_TRUST_TAMPER_001 | HIGH | jsrisk | Host trust surface tampering |
| <a id="js_obf_001"></a>JS_OBF_001 | MEDIUM | jsrisk | Large obfuscated JavaScript payload |
| <a id="js_proc_mem_oidc_001"></a>JS_PROC_MEM_OIDC_001 | CRITICAL | jsrisk | Runner process memory access combined with OIDC token reference |
| <a id="js_sudoers_tamper_001"></a>JS_SUDOERS_TAMPER_001 | HIGH | jsrisk | Sudoers privilege tampering |
| <a id="js_wiper_tripwire_001"></a>JS_WIPER_TRIPWIRE_001 | HIGH | jsrisk | Destructive wipe of sensitive paths |
| <a id="py_importtime_remote_js_001"></a>PY_IMPORTTIME_REMOTE_JS_001 | CRITICAL | pyrisk | PyPI import-time remote JavaScript execution |
| <a id="rs_build_wallet_exfil_001"></a>RS_BUILD_WALLET_EXFIL_001 | CRITICAL | rsbuild | Rust build.rs wallet/keystore exfiltration |
| <a id="npm_allow_git_relaxed_001"></a>NPM_ALLOW_GIT_RELAXED_001 | MEDIUM | npm-policy | npm git-dependency resolution pinned open |
| <a id="npm_allow_remote_relaxed_001"></a>NPM_ALLOW_REMOTE_RELAXED_001 | MEDIUM | npm-policy | npm remote-tarball resolution pinned open |
| <a id="npm_allow_scripts_unpinned_001"></a>NPM_ALLOW_SCRIPTS_UNPINNED_001 | MEDIUM | npm-policy | npm allowScripts approval not version-pinned |
| <a id="npm_dangerous_all_scripts_001"></a>NPM_DANGEROUS_ALL_SCRIPTS_001 | HIGH | npm-policy | npm dangerously-allow-all-scripts enabled |
| <a id="pnpm_build_approval_pending_001"></a>PNPM_BUILD_APPROVAL_PENDING_001 | MEDIUM | pnpm-policy | pnpm allowBuilds entry pending decision |
| <a id="pnpm_dangerous_builds_001"></a>PNPM_DANGEROUS_BUILDS_001 | HIGH | pnpm-policy | pnpm dangerouslyAllowAllBuilds enabled |
| <a id="pnpm_exotic_subdeps_disabled_001"></a>PNPM_EXOTIC_SUBDEPS_DISABLED_001 | MEDIUM | pnpm-policy | pnpm blockExoticSubdeps disabled |
| <a id="pnpm_legacy_build_policy_001"></a>PNPM_LEGACY_BUILD_POLICY_001 | INFO | pnpm-policy | pnpm legacy v10 build-policy setting |
| <a id="pnpm_min_release_age_disabled_001"></a>PNPM_MIN_RELEASE_AGE_DISABLED_001 | LOW | pnpm-policy | pnpm minimumReleaseAge disabled |
| <a id="pnpm_min_release_age_non_strict_001"></a>PNPM_MIN_RELEASE_AGE_NON_STRICT_001 | LOW | pnpm-policy | pnpm minimumReleaseAge not strictly enforced |
| <a id="pnpm_strict_dep_builds_disabled_001"></a>PNPM_STRICT_DEP_BUILDS_DISABLED_001 | MEDIUM | pnpm-policy | pnpm strictDepBuilds disabled |
| <a id="pnpm_trust_lockfile_001"></a>PNPM_TRUST_LOCKFILE_001 | MEDIUM | pnpm-policy | pnpm trustLockfile enabled |
| <a id="pnpm_trust_policy_off_001"></a>PNPM_TRUST_POLICY_OFF_001 | LOW | pnpm-policy | pnpm trustPolicy explicitly off |
| <a id="py_world_writable_001"></a>PY_WORLD_WRITABLE_001 | MEDIUM | script-risk | Python code applies world-writable permissions |
| <a id="shell_unsafe_npm_source_001"></a>SHELL_UNSAFE_NPM_SOURCE_001 | MEDIUM | script-risk | Unencrypted npm dependency source in a script |
| <a id="shell_unsafe_pip_source_001"></a>SHELL_UNSAFE_PIP_SOURCE_001 | MEDIUM | script-risk | Unencrypted pip dependency source in a script |

## Supply Chain Exfil (14)

Category `supply-chain-exfil`: 10 pattern rules, 4 analyzer-emitted (`script-risk`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="sc-ex-001"></a>SC-EX-001 | CRITICAL | pattern | Credential file read in Python code |
| <a id="sc-ex-002"></a>SC-EX-002 | CRITICAL | pattern | File content encoding for exfiltration |
| <a id="sc-ex-003"></a>SC-EX-003 | CRITICAL | pattern | Environment variable bulk collection with network send |
| <a id="sc-ex-004"></a>SC-EX-004 | CRITICAL | pattern | .pth file with executable content |
| <a id="sc-ex-005"></a>SC-EX-005 | HIGH | pattern | Cloud metadata endpoint access in Python |
| <a id="sc-ex-006"></a>SC-EX-006 | CRITICAL | pattern | Kubernetes secrets API access outside K8s libraries |
| <a id="sc-ex-008"></a>SC-EX-008 | HIGH | pattern | Hardcoded cryptographic key material |
| <a id="sc-ex-009"></a>SC-EX-009 | CRITICAL | pattern | Archive creation combined with HTTP POST |
| <a id="sc-ex-010"></a>SC-EX-010 | MEDIUM | pattern | .pth file presence with non-path content |
| <a id="supply_024"></a>SUPPLY_024 | HIGH | pattern | Session-Network exfil endpoint |
| <a id="py_context_exfil_001"></a>PY_CONTEXT_EXFIL_001 | HIGH | script-risk | Sensitive local context paired with network transmission |
| <a id="py_decode_exec_001"></a>PY_DECODE_EXEC_001 | CRITICAL | script-risk | Obfuscated Python payload execution |
| <a id="py_remote_fetch_exec_001"></a>PY_REMOTE_FETCH_EXEC_001 | CRITICAL | script-risk | Remote Python payload execution |
| <a id="sc-ex-007"></a>SC-EX-007 | CRITICAL | script-risk | Systemd or cron persistence installation |

## External Download (16)

Category `external-download`: 16 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="extdl_001"></a>EXTDL_001 | HIGH | pattern | Runtime URL controls agent behavior |
| <a id="extdl_002"></a>EXTDL_002 | MEDIUM | pattern | Remote SDK or script fetch as agent input |
| <a id="extdl_003"></a>EXTDL_003 | LOW | pattern | npx auto-install without confirmation |
| <a id="extdl_004"></a>EXTDL_004 | LOW | pattern | Global package installation |
| <a id="extdl_005"></a>EXTDL_005 | MEDIUM | pattern | Shell profile modification for persistence |
| <a id="extdl_006"></a>EXTDL_006 | HIGH | pattern | MCP server auto-registration |
| <a id="extdl_007"></a>EXTDL_007 | CRITICAL | pattern | Binary download and execute |
| <a id="extdl_008"></a>EXTDL_008 | LOW | pattern | Unverified npx package execution |
| <a id="extdl_009"></a>EXTDL_009 | LOW | pattern | pip install arbitrary package |
| <a id="extdl_010"></a>EXTDL_010 | LOW | pattern | go install from remote |
| <a id="extdl_011"></a>EXTDL_011 | LOW | pattern | System package manager install |
| <a id="extdl_012"></a>EXTDL_012 | LOW | pattern | Cargo or gem install from remote |
| <a id="extdl_013"></a>EXTDL_013 | CRITICAL | pattern | Curl or wget piped to shell |
| <a id="extdl_014"></a>EXTDL_014 | MEDIUM | pattern | Conditional download and install |
| <a id="extdl_015"></a>EXTDL_015 | MEDIUM | pattern | Docker pull and run untrusted image |
| <a id="extdl_016"></a>EXTDL_016 | MEDIUM | pattern | Download binary or archive from URL |

## Command Execution (16)

Category `command-execution`: 16 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="cmdexec_001"></a>CMDEXEC_001 | MEDIUM | pattern | Shell subprocess with shell=True |
| <a id="cmdexec_002"></a>CMDEXEC_002 | MEDIUM | pattern | Dynamic code evaluation |
| <a id="cmdexec_003"></a>CMDEXEC_003 | MEDIUM | pattern | Python subprocess execution |
| <a id="cmdexec_004"></a>CMDEXEC_004 | HIGH | pattern | Node.js child process execution |
| <a id="cmdexec_005"></a>CMDEXEC_005 | HIGH | pattern | Shell command with dangerous payload |
| <a id="cmdexec_006"></a>CMDEXEC_006 | HIGH | pattern | Java/Go command execution API |
| <a id="cmdexec_007"></a>CMDEXEC_007 | HIGH | pattern | PowerShell command execution |
| <a id="cmdexec_008"></a>CMDEXEC_008 | MEDIUM | pattern | Terminal multiplexer command injection |
| <a id="cmdexec_009"></a>CMDEXEC_009 | MEDIUM | pattern | Agent shell tool usage |
| <a id="cmdexec_010"></a>CMDEXEC_010 | MEDIUM | pattern | MCP code execution tool |
| <a id="cmdexec_011"></a>CMDEXEC_011 | MEDIUM | pattern | Cron or scheduled command execution |
| <a id="cmdexec_012"></a>CMDEXEC_012 | LOW | pattern | Chained shell command execution |
| <a id="cmdexec_013"></a>CMDEXEC_013 | LOW | pattern | Shell script file execution |
| <a id="cmdexec_014"></a>CMDEXEC_014 | HIGH | pattern | Hex or octal escape obfuscation |
| <a id="cmdexec_015"></a>CMDEXEC_015 | HIGH | pattern | Process substitution or eval-download execution |
| <a id="indirect_010"></a>INDIRECT_010 | LOW | pattern | Unscoped Bash tool in allowed tools |

## Indirect Injection (10)

Category `indirect-injection`: 10 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="indirect_001"></a>INDIRECT_001 | HIGH | pattern | Fetch URL and use as instructions |
| <a id="indirect_003"></a>INDIRECT_003 | HIGH | pattern | Read external content and apply as rules |
| <a id="indirect_004"></a>INDIRECT_004 | HIGH | pattern | Remote config controlling agent behavior |
| <a id="indirect_005"></a>INDIRECT_005 | LOW | pattern | User-provided URL consumed by agent |
| <a id="indirect_008"></a>INDIRECT_008 | HIGH | pattern | Email or message content as instructions |
| <a id="indirect_009"></a>INDIRECT_009 | MEDIUM | pattern | External API response drives agent behavior |
| <a id="indirect_011"></a>INDIRECT_011 | HIGH | pattern | Database or cache query driving agent behavior |
| <a id="indirect_012"></a>INDIRECT_012 | HIGH | pattern | Webhook or callback registration with external service |
| <a id="indirect_013"></a>INDIRECT_013 | HIGH | pattern | Git clone and execute fetched code |
| <a id="indirect_014"></a>INDIRECT_014 | MEDIUM | pattern | Environment variable injection from external source |

## Third-Party Content (10)

Category `third-party-content`: 10 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="thirdparty_001"></a>THIRDPARTY_001 | LOW | pattern | Runtime URL controlling behavior |
| <a id="thirdparty_002"></a>THIRDPARTY_002 | LOW | pattern | Mutable GitHub raw content reference |
| <a id="thirdparty_003"></a>THIRDPARTY_003 | HIGH | pattern | JavaScript eval or Function with external data |
| <a id="thirdparty_004"></a>THIRDPARTY_004 | LOW | pattern | External API response used without validation |
| <a id="thirdparty_005"></a>THIRDPARTY_005 | HIGH | pattern | Remote template or prompt loaded at runtime |
| <a id="thirdparty_006"></a>THIRDPARTY_006 | HIGH | pattern | Unescaped user input in HTML output |
| <a id="thirdparty_007"></a>THIRDPARTY_007 | HIGH | pattern | Unsafe deserialization from untrusted source |
| <a id="thirdparty_008"></a>THIRDPARTY_008 | MEDIUM | pattern | Script or asset loaded without integrity check |
| <a id="thirdparty_009"></a>THIRDPARTY_009 | MEDIUM | pattern | HTTP downgrade from HTTPS |
| <a id="thirdparty_010"></a>THIRDPARTY_010 | HIGH | pattern | Unsigned plugin or extension loading |

## SSRF & Cloud (11)

Category `ssrf-cloud`: 11 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="ssrf_001"></a>SSRF_001 | CRITICAL | pattern | Cloud metadata URL |
| <a id="ssrf_002"></a>SSRF_002 | HIGH | pattern | Internal IP range access |
| <a id="ssrf_003"></a>SSRF_003 | HIGH | pattern | Kubernetes service discovery |
| <a id="ssrf_004"></a>SSRF_004 | CRITICAL | pattern | AWS IMDS token request |
| <a id="ssrf_005"></a>SSRF_005 | HIGH | pattern | Docker socket access |
| <a id="ssrf_006"></a>SSRF_006 | HIGH | pattern | Localhost bypass |
| <a id="ssrf_007"></a>SSRF_007 | CRITICAL | pattern | Cloud credential endpoint |
| <a id="ssrf_008"></a>SSRF_008 | MEDIUM | pattern | DNS rebinding setup |
| <a id="ssrf_009"></a>SSRF_009 | HIGH | pattern | IPv4 alternative numeric encoding |
| <a id="ssrf_010"></a>SSRF_010 | HIGH | pattern | IPv6 transition address with embedded IPv4 |
| <a id="ssrf_011"></a>SSRF_011 | HIGH | pattern | IPv6 multicast SSRF bypass |

## Unicode Attack (10)

Category `unicode-attack`: 10 pattern rules.

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="uni_001"></a>UNI_001 | HIGH | pattern | Right-to-left override |
| <a id="uni_002"></a>UNI_002 | HIGH | pattern | Bidi text manipulation |
| <a id="uni_003"></a>UNI_003 | MEDIUM | pattern | Homoglyph domain spoofing |
| <a id="uni_004"></a>UNI_004 | MEDIUM | pattern | Invisible separator injection |
| <a id="uni_005"></a>UNI_005 | MEDIUM | pattern | Combining character obfuscation |
| <a id="uni_006"></a>UNI_006 | HIGH | pattern | Tag characters for hidden data |
| <a id="uni_007"></a>UNI_007 | MEDIUM | pattern | Punycode domains |
| <a id="uni_008"></a>UNI_008 | MEDIUM | pattern | Zero-width character sequences |
| <a id="uni_009"></a>UNI_009 | MEDIUM | pattern | Unicode normalization inconsistency |
| <a id="uni_010"></a>UNI_010 | MEDIUM | pattern | Mixed-script confusable in identifiers |

## Toxic Flow (6)

Category `toxic-flow`: 6 analyzer-emitted (`toxicflow`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="toxic_001"></a>TOXIC_001 | HIGH | toxicflow | Private data read with public output |
| <a id="toxic_002"></a>TOXIC_002 | HIGH | toxicflow | Private data read with code execution |
| <a id="toxic_003"></a>TOXIC_003 | HIGH | toxicflow | Destructive actions with code execution |
| <a id="toxic_cross_001"></a>TOXIC_CROSS_001 | HIGH | toxicflow | Cross-file credential exfiltration across MCP tools |
| <a id="toxic_cross_002"></a>TOXIC_CROSS_002 | HIGH | toxicflow | Cross-file env-to-exec chain across MCP tools |
| <a id="toxic_cross_003"></a>TOXIC_CROSS_003 | HIGH | toxicflow | Cross-file destructive + exec combo across MCP tools |

## Agent Trust (10)

Category `agent-trust`: 10 analyzer-emitted (`agent-policy`, `skill-policy`, `skill-chain`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="agentcfg_broad_allow_001"></a>AGENTCFG_BROAD_ALLOW_001 | MEDIUM | agent-policy | Claude Code permissions pre-approve dangerous commands |
| <a id="agentcfg_bypass_perms_001"></a>AGENTCFG_BYPASS_PERMS_001 | HIGH | agent-policy | Claude Code permissions default to bypass |
| <a id="agentcfg_env_exec_001"></a>AGENTCFG_ENV_EXEC_001 | HIGH | agent-policy | Claude Code settings inject a code-execution environment variable |
| <a id="agentcfg_helper_repo_script_001"></a>AGENTCFG_HELPER_REPO_SCRIPT_001 | MEDIUM | agent-policy | Claude Code credential helper runs a repo-shipped script |
| <a id="agentcfg_hook_fetch_exec_001"></a>AGENTCFG_HOOK_FETCH_EXEC_001 | CRITICAL | agent-policy | Claude Code hook downloads and executes remote code |
| <a id="agentcfg_mcp_autoapprove_001"></a>AGENTCFG_MCP_AUTOAPPROVE_001 | MEDIUM | agent-policy | Claude Code auto-approves all project MCP servers |
| <a id="agentcfg_perms_weak_mode_001"></a>AGENTCFG_PERMS_WEAK_MODE_001 | LOW | agent-policy | Claude Code permissions default to an auto-approving mode |
| <a id="agentcfg_secret_read_allow_001"></a>AGENTCFG_SECRET_READ_ALLOW_001 | MEDIUM | agent-policy | Claude Code permissions pre-approve reading secrets |
| <a id="agent_skill_wildcard_tools_001"></a>AGENT_SKILL_WILDCARD_TOOLS_001 | MEDIUM | skill-policy | Skill pre-approves every tool |
| <a id="agent_forced_helper_risk_001"></a>AGENT_FORCED_HELPER_RISK_001 | HIGH | skill-chain | Mandatory skill helper contains hidden high-risk behavior |

## Container Security (1)

Category `container-security`: 1 analyzer-emitted (`kube-policy`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="k8s_identity_capabilities_001"></a>K8S_IDENTITY_CAPABILITIES_001 | LOW | kube-policy | Kubernetes workload requests identity-changing capabilities |

## Rug Pull (1)

Category `rug-pull`: 1 analyzer-emitted (`rugpull`).

| Rule | Severity | Source | Name |
|------|----------|--------|------|
| <a id="rugpull_001"></a>RUGPULL_001 | CRITICAL | rugpull | Tool description changed with dangerous content |

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

An optional `cwe` list names the CWE weaknesses a rule detects, for example `cwe: [CWE-798]` for a hard-coded credential. Entries must have the form `CWE-<number>`. SARIF output turns them into `external/cwe/cwe-<number>` tags, with the number zero-padded to three digits as CodeQL writes them (`external/cwe/cwe-079`), and CWE taxonomy references, and `aguara explain` and `list-rules --format json` show them. Add a CWE only when the mapping is unambiguous: a CWE names a weakness in the scanned code or content, so a rule that detects an attack payload aimed at someone else's weakness (SUPPLY_009's `../../etc/passwd` traversal strings, SUPPLY_010's symlinks to sensitive files) is left unmapped. Most built-in rules have none. Rule files that use `cwe` fail to load on releases before the one that introduced the field.

Load custom rules with the `--rules` flag:

```bash
aguara scan .claude/skills/ --rules ./my-rules/
```

Repeat `--rules` to load several directories (`--rules ./team-rules/ --rules ./my-rules/`).
The directory may be a symbolic link. Inside it, symlinked rule files are read
from their target; symlinked subdirectories are not followed and are reported
as a configuration problem.

See the [Contributing Guide](CONTRIBUTING.md) for more details on rule structure and testing.
