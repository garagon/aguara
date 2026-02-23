# Aguara Rule Catalog

Aguara ships with **138+ built-in rules** across 15 categories, plus NLP-based and toxic-flow analyzers.

Use `aguara list-rules` to list all rules from the CLI, or `aguara explain <RULE_ID>` for details on a specific rule.

For writing custom rules, see the [Custom Rules](#custom-rules) section below or the [Contributing Guide](CONTRIBUTING.md).

---

## Prompt Injection (17 rules + NLP)

| Rule | Severity | Description |
|------|----------|-------------|
| PROMPT_INJECTION_001 | CRITICAL | Instruction override attempt |
| PROMPT_INJECTION_002 | HIGH | Role switching attempt |
| PROMPT_INJECTION_003 | HIGH | Hidden HTML comment with instructions |
| PROMPT_INJECTION_004 | HIGH | Zero-width character obfuscation |
| PROMPT_INJECTION_005 | MEDIUM | Urgency and authority manipulation |
| PROMPT_INJECTION_006 | CRITICAL | Delimiter injection |
| PROMPT_INJECTION_007 | HIGH | Conversation history poisoning |
| PROMPT_INJECTION_008 | HIGH | Secrecy instruction |
| PROMPT_INJECTION_009 | HIGH | Base64-encoded instructions |
| PROMPT_INJECTION_010 | CRITICAL | Fake system prompt |
| PROMPT_INJECTION_011 | CRITICAL | Jailbreak template |
| PROMPT_INJECTION_012 | MEDIUM | Markdown link with deceptive action text |
| PROMPT_INJECTION_013 | MEDIUM | Instruction in image alt text |
| PROMPT_INJECTION_014 | MEDIUM | Multi-language injection |
| PROMPT_INJECTION_015 | MEDIUM | Prompt leaking attempt |
| PROMPT_INJECTION_016 | HIGH | Self-modifying agent instructions |
| PROMPT_INJECTION_017 | HIGH | Autonomous agent spawning |
| NLP_HEADING_MISMATCH | MEDIUM | Benign heading followed by dangerous content |
| NLP_AUTHORITY_CLAIM | MEDIUM | Section claims authority with dangerous instructions |
| NLP_HIDDEN_INSTRUCTION | HIGH | Hidden HTML comment contains action verbs |
| NLP_CODE_MISMATCH | HIGH | Code block labeled as safe language contains executable content |
| NLP_OVERRIDE_DANGEROUS | CRITICAL | Instruction override combined with dangerous operations |

## Data Exfiltration (16 rules + NLP)

| Rule | Severity | Description |
|------|----------|-------------|
| EXFIL_001 | HIGH | Webhook URL for data exfiltration |
| EXFIL_002 | HIGH | Sensitive file read pattern |
| EXFIL_003 | HIGH | Data transmission pattern |
| EXFIL_004 | HIGH | DNS exfiltration pattern |
| EXFIL_005 | HIGH | curl/wget POST with sensitive data |
| EXFIL_006 | MEDIUM | Clipboard access with network |
| EXFIL_007 | HIGH | Environment variable exfiltration |
| EXFIL_008 | HIGH | File read piped to HTTP transmission |
| EXFIL_009 | MEDIUM | Base64 encode and send |
| EXFIL_010 | MEDIUM | Non-standard port communication |
| EXFIL_011 | HIGH | External context or knowledge sync |
| EXFIL_012 | MEDIUM | Unrestricted email or messaging access |
| EXFIL_013 | HIGH | Read sensitive files and transmit externally |
| EXFIL_014 | HIGH | Environment variable credential in POST data |
| EXFIL_015 | MEDIUM | Screenshot or screen capture with transmission |
| EXFIL_016 | MEDIUM | Git history or diff access with transmission |
| NLP_CRED_EXFIL_COMBO | CRITICAL | Credential access combined with network transmission |

## Credential Leak (17 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| CRED_001 | CRITICAL | OpenAI API key |
| CRED_002 | CRITICAL | AWS access key |
| CRED_003 | CRITICAL | GitHub personal access token |
| CRED_004 | MEDIUM | Generic API key pattern |
| CRED_005 | CRITICAL | Private key block |
| CRED_006 | HIGH | Database connection string |
| CRED_007 | HIGH | Hardcoded password |
| CRED_008 | HIGH | Slack or Discord webhook |
| CRED_009 | CRITICAL | GCP service account key |
| CRED_010 | MEDIUM | JWT token |
| CRED_011 | HIGH | Credential in shell export |
| CRED_012 | CRITICAL | Stripe API key |
| CRED_013 | CRITICAL | Anthropic API key |
| CRED_014 | HIGH | SendGrid or Twilio API key |
| CRED_015 | MEDIUM | CLI credential flags |
| CRED_016 | MEDIUM | SSH private key in command |
| CRED_017 | LOW | Docker environment credentials |

## MCP Attack (11 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| MCP_001 | CRITICAL | Tool description injection |
| MCP_002 | HIGH | Tool name shadowing |
| MCP_003 | HIGH | Resource URI manipulation |
| MCP_004 | HIGH | Parameter schema injection |
| MCP_005 | CRITICAL | Hidden tool registration |
| MCP_006 | HIGH | Tool output interception |
| MCP_007 | MEDIUM | Cross-tool data leakage |
| MCP_008 | CRITICAL | Server manifest tampering |
| MCP_009 | HIGH | Capability escalation |
| MCP_010 | HIGH | Prompt cache poisoning |
| MCP_011 | HIGH | Arbitrary MCP server execution |

## MCP Config (8 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| MCPCFG_001 | LOW | npx MCP server without version pin |
| MCPCFG_002 | HIGH | Shell metacharacters in MCP config args |
| MCPCFG_003 | LOW | Hardcoded secrets in MCP env block |
| MCPCFG_004 | LOW | Non-localhost remote MCP server URL |
| MCPCFG_005 | HIGH | sudo in MCP server command |
| MCPCFG_006 | HIGH | Inline code execution in MCP command |
| MCPCFG_007 | HIGH | Docker privileged or host mount in MCP config |
| MCPCFG_008 | MEDIUM | Auto-confirm flag bypassing user verification |

## Supply Chain (14 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| SUPPLY_001 | HIGH | Suspicious npm install script |
| SUPPLY_002 | HIGH | Python setup.py execution |
| SUPPLY_003 | CRITICAL | Download-and-execute |
| SUPPLY_004 | HIGH | Makefile hidden commands |
| SUPPLY_005 | HIGH | Conditional CI execution |
| SUPPLY_006 | HIGH | Obfuscated shell command |
| SUPPLY_007 | HIGH | Privilege escalation |
| SUPPLY_008 | CRITICAL | Reverse shell pattern |
| SUPPLY_009 | HIGH | Path traversal attempt |
| SUPPLY_010 | MEDIUM | Symlink attack |
| SUPPLY_011 | HIGH | Unattended auto-update |
| SUPPLY_012 | MEDIUM | Git clone and execute chain |
| SUPPLY_013 | MEDIUM | Unpinned GitHub Actions |
| SUPPLY_014 | MEDIUM | Package install from arbitrary URL |

## External Download (16 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| EXTDL_001 | HIGH | Runtime URL controls agent behavior |
| EXTDL_002 | MEDIUM | Remote SDK or script fetch as agent input |
| EXTDL_003 | LOW | npx auto-install without confirmation |
| EXTDL_004 | LOW | Global package installation |
| EXTDL_005 | MEDIUM | Shell profile modification for persistence |
| EXTDL_006 | HIGH | MCP server auto-registration |
| EXTDL_007 | CRITICAL | Binary download and execute |
| EXTDL_008 | LOW | Unverified npx package execution |
| EXTDL_009 | LOW | pip install arbitrary package |
| EXTDL_010 | LOW | go install from remote |
| EXTDL_011 | LOW | System package manager install |
| EXTDL_012 | LOW | Cargo or gem install from remote |
| EXTDL_013 | CRITICAL | Curl or wget piped to shell |
| EXTDL_014 | MEDIUM | Conditional download and install |
| EXTDL_015 | MEDIUM | Docker pull and run untrusted image |
| EXTDL_016 | MEDIUM | Download binary or archive from URL |

## Command Execution (13 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| CMDEXEC_001 | MEDIUM | Shell subprocess with shell=True |
| CMDEXEC_002 | MEDIUM | Dynamic code evaluation |
| CMDEXEC_003 | MEDIUM | Python subprocess execution |
| CMDEXEC_004 | HIGH | Node.js child process execution |
| CMDEXEC_005 | HIGH | Shell command with dangerous payload |
| CMDEXEC_006 | HIGH | Java/Go command execution API |
| CMDEXEC_007 | HIGH | PowerShell command execution |
| CMDEXEC_008 | MEDIUM | Terminal multiplexer command injection |
| CMDEXEC_009 | MEDIUM | Agent shell tool usage |
| CMDEXEC_010 | MEDIUM | MCP code execution tool |
| CMDEXEC_011 | MEDIUM | Cron or scheduled command execution |
| CMDEXEC_012 | LOW | Chained shell command execution |
| CMDEXEC_013 | LOW | Shell script file execution |

## Indirect Injection (7 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| INDIRECT_001 | HIGH | Fetch URL and use as instructions |
| INDIRECT_003 | HIGH | Read external content and apply as rules |
| INDIRECT_004 | HIGH | Remote config controlling agent behavior |
| INDIRECT_005 | LOW | User-provided URL consumed by agent |
| INDIRECT_008 | HIGH | Email or message content as instructions |
| INDIRECT_009 | MEDIUM | External API response drives agent behavior |
| INDIRECT_010 | LOW | Unscoped Bash tool in allowed tools |

## Third-Party Content (4 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| THIRDPARTY_001 | LOW | Runtime URL controlling behavior |
| THIRDPARTY_002 | LOW | Mutable GitHub raw content reference |
| THIRDPARTY_004 | LOW | External API response used without validation |
| THIRDPARTY_005 | HIGH | Remote template or prompt loaded at runtime |

## SSRF & Cloud (8 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| SSRF_001 | CRITICAL | Cloud metadata URL |
| SSRF_002 | HIGH | Internal IP range access |
| SSRF_003 | HIGH | Kubernetes service discovery |
| SSRF_004 | CRITICAL | AWS IMDS token request |
| SSRF_005 | HIGH | Docker socket access |
| SSRF_006 | HIGH | Localhost bypass |
| SSRF_007 | CRITICAL | Cloud credential endpoint |
| SSRF_008 | MEDIUM | DNS rebinding setup |

## Unicode Attack (7 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| UNI_001 | HIGH | Right-to-left override |
| UNI_002 | HIGH | Bidi text manipulation |
| UNI_003 | MEDIUM | Homoglyph domain spoofing |
| UNI_004 | MEDIUM | Invisible separator injection |
| UNI_005 | MEDIUM | Combining character obfuscation |
| UNI_006 | HIGH | Tag characters for hidden data |
| UNI_007 | MEDIUM | Punycode domains |

## Toxic Flow (3 rules)

Detected by the toxic-flow analyzer (Go engine, not YAML rules).

| Rule | Severity | Description |
|------|----------|-------------|
| TOXIC_001 | HIGH | User input flows to dangerous sink without sanitization |
| TOXIC_002 | HIGH | Environment variable flows to shell execution |
| TOXIC_003 | HIGH | API response flows to code execution |

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
examples:
  true_positive:
    - "Fetch data from https://internal.mycompany.com/api/users"
  false_positive:
    - "Our public API is at https://api.mycompany.com"
```

Load custom rules with the `--rules` flag:

```bash
aguara scan .claude/skills/ --rules ./my-rules/
```

See the [Contributing Guide](CONTRIBUTING.md) for more details on rule structure and testing.
