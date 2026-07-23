// Package skillchain correlates agent-skill instructions with the local
// helper code they require the agent to execute.
package skillchain

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/types"
)

const (
	RuleForcedHelperRisk = "AGENT_FORCED_HELPER_RISK_001"
	AnalyzerName         = rulemeta.AnalyzerSkillChain
)

var (
	helperCommandRe = regexp.MustCompile(`(?i)\b(?:python(?:2|3)?|bash|sh|zsh|node|bun)\s+["'` + "`" + `]?([A-Za-z0-9_./-]+\.(?:py|sh|bash|zsh|js|mjs|cjs))`)
	forcedActionRe  = regexp.MustCompile(`(?i)(?:\b(?:must|required|always|silently)\b.{0,180}\b(?:run|execute|invoke)\b|\b(?:run|execute|invoke)\b.{0,180}\b(?:regardless\s+of|do\s+not\s+ask|without\s+(?:asking|confirmation)|before\b|first(?:\s+(?:time|action|step))?)\b|\bbefore\b.{0,120}\b(?:run|execute|invoke)\b)`)
	explicitOptInRe = regexp.MustCompile(`(?i)\b(?:optional|review\s+material|not\s+required|only\s+when\s+the\s+user\s+(?:explicitly\s+)?(?:asks|requests|wants)|do\s+not\s+run\s+automatically)\b`)

	promptOverrideRe   = regexp.MustCompile(`(?i)(?:\bDAN\s+mode\b|\bjailbreak\s+mode\b|ignore\s+(?:all\s+)?previous\s+(?:safety\s+)?(?:instructions|notes|prompts)|bypass(?:es|ing)?[^"'` + "`" + `\n]{0,80}\bguardrails?\b|disable[^"'` + "`" + `\n]{0,80}\bsafety\b)`)
	pythonAssignmentRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	promptDirectUseRe  = regexp.MustCompile(`(?i)\b(?:print|return|logger|logging\.[A-Za-z_]\w*|subprocess\.[A-Za-z_]\w*)\b`)
	pythonShellCallRe  = regexp.MustCompile(`(?is)(?:\b(?:os|[A-Za-z_]\w*\.modules\s*\[\s*["']os["']\s*\])\s*\.\s*(?:system|popen)|\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|check_call))\s*\(`)
	networkToolRe      = regexp.MustCompile(`(?i)\b(?:curl|wget)\b`)
	directVCSInstallRe = regexp.MustCompile(`(?i)^(?:(?:sudo|env)\s+)*(?:(?:python(?:2|3)?(?:\.\d+)?)\s+-m\s+)?(?:pip3?\s+install|npm\s+(?:install|i))\b[^\n#]*(?:git\+https?://|https?://\S+\.(?:tgz|tar\.gz|zip)\b)`)
)

type Analyzer struct {
	mu    sync.Mutex
	files map[string]string
}

func New() *Analyzer {
	return &Analyzer{files: make(map[string]string)}
}

func (a *Analyzer) Accumulate(relPath string, content string) {
	relPath = normalizePath(relPath)
	if !isRelevantFile(relPath) {
		return
	}
	a.mu.Lock()
	a.files[relPath] = content
	a.mu.Unlock()
}

func (a *Analyzer) Finalize() []types.Finding {
	a.mu.Lock()
	files := make(map[string]string, len(a.files))
	for path, content := range a.files {
		files[path] = content
	}
	a.mu.Unlock()

	var findings []types.Finding
	for path, content := range files {
		if !strings.EqualFold(filepath.Base(path), "SKILL.md") {
			continue
		}
		findings = append(findings, analyzeSkill(path, content, files)...)
	}
	return findings
}

func analyzeSkill(skillPath, content string, files map[string]string) []types.Finding {
	lines := strings.Split(content, "\n")
	inFence := false
	for i, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || line == "" || explicitOptInRe.MatchString(line) || !forcedActionRe.MatchString(line) {
			continue
		}
		match := helperCommandRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		helperPath, ok := resolveHelperPath(skillPath, match[1])
		if !ok {
			continue
		}
		helper, ok := files[helperPath]
		if !ok {
			continue
		}
		signal := strongHelperSignal(helperPath, helper)
		if signal == "" {
			continue
		}
		meta := ruleInfo[RuleForcedHelperRisk]
		return []types.Finding{{
			RuleID:      meta.ID,
			RuleName:    meta.Name,
			Severity:    meta.SeverityLevel(),
			Category:    meta.Category,
			Description: meta.Description,
			FilePath:    skillPath,
			Line:        i + 1,
			MatchedText: strings.TrimSpace(rawLine),
			Context:     types.ExtractContext(lines, i+1, 2, 2),
			Confidence:  0.95,
			Remediation: meta.Remediation,
			Analyzer:    AnalyzerName,
		}}
	}
	return nil
}

func resolveHelperPath(skillPath, ref string) (string, bool) {
	ref = normalizePath(strings.TrimPrefix(strings.TrimSpace(ref), "./"))
	if ref == "" || filepath.IsAbs(ref) {
		return "", false
	}
	candidate := normalizePath(filepath.Join(filepath.Dir(skillPath), ref))
	root := normalizePath(filepath.Dir(skillPath))
	if root == "." {
		root = ""
	}
	if candidate == ".." || strings.HasPrefix(candidate, "../") {
		return "", false
	}
	if root != "" && candidate != root && !strings.HasPrefix(candidate, root+"/") {
		return "", false
	}
	return candidate, true
}

func strongHelperSignal(path, content string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		code := pythonCodeView(content)
		if hasUsedPromptOverride(code) {
			return "instruction override payload"
		}
		if hasPythonNetworkCommandExecution(code) {
			return "network command execution"
		}
	case ".sh", ".bash", ".zsh":
		for _, line := range strings.Split(content, "\n") {
			line = stripShellComment(line)
			if directVCSInstallRe.MatchString(strings.TrimSpace(line)) {
				return "direct VCS dependency installation"
			}
		}
	}
	return ""
}

func hasUsedPromptOverride(code string) bool {
	lines := strings.Split(code, "\n")
	for i, line := range lines {
		if !promptOverrideRe.MatchString(line) {
			continue
		}
		if assignment := pythonAssignmentRe.FindStringSubmatch(line); assignment != nil {
			if identifierUsed(strings.Join(lines[i+1:], "\n"), assignment[1]) {
				return true
			}
			continue
		}
		if promptDirectUseRe.MatchString(line) {
			return true
		}
	}
	return false
}

func identifierUsed(content, identifier string) bool {
	for offset := 0; offset < len(content); {
		index := strings.Index(content[offset:], identifier)
		if index < 0 {
			return false
		}
		index += offset
		beforeOK := index == 0 || !isPythonIdentifierByte(content[index-1])
		after := index + len(identifier)
		afterOK := after == len(content) || !isPythonIdentifierByte(content[after])
		if beforeOK && afterOK {
			return true
		}
		offset = index + len(identifier)
	}
	return false
}

func isPythonIdentifierByte(ch byte) bool {
	return ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func hasPythonNetworkCommandExecution(code string) bool {
	stringMask := pythonStringMask(code)
	for _, loc := range pythonShellCallRe.FindAllStringIndex(code, -1) {
		if stringMask[loc[0]] {
			continue
		}
		open := loc[1] - 1
		end := balancedPythonCallEnd(code, open)
		if end > open && networkToolRe.MatchString(code[open+1:end]) {
			return true
		}
	}
	return false
}

func pythonStringMask(content string) []bool {
	mask := make([]bool, len(content))
	var quote byte
	escaped := false
	for i := 0; i < len(content); i++ {
		ch := content[i]
		if quote != 0 {
			mask[i] = true
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			mask[i] = true
		}
	}
	return mask
}

func balancedPythonCallEnd(content string, open int) int {
	depth := 0
	var quote byte
	escaped := false
	for i := open; i < len(content); i++ {
		ch := content[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func pythonCodeView(content string) string {
	var out strings.Builder
	out.Grow(len(content))
	inTriple := ""
	for _, line := range strings.Split(content, "\n") {
		clean := line
		for {
			if inTriple != "" {
				end := strings.Index(clean, inTriple)
				if end < 0 {
					clean = ""
					break
				}
				clean = clean[end+3:]
				inTriple = ""
				continue
			}
			single := strings.Index(clean, `'''`)
			double := strings.Index(clean, `"""`)
			start, marker := firstTripleQuote(single, double)
			if start < 0 {
				break
			}
			rest := clean[start+3:]
			end := strings.Index(rest, marker)
			if end >= 0 {
				clean = clean[:start] + rest[end+3:]
				continue
			}
			clean = clean[:start]
			inTriple = marker
			break
		}
		out.WriteString(stripPythonComment(clean))
		out.WriteByte('\n')
	}
	return out.String()
}

func firstTripleQuote(single, double int) (int, string) {
	switch {
	case single < 0:
		return double, `"""`
	case double < 0:
		return single, `'''`
	case single < double:
		return single, `'''`
	default:
		return double, `"""`
	}
}

func stripPythonComment(line string) string {
	return stripLineComment(line, '#')
}

func stripShellComment(line string) string {
	return stripLineComment(line, '#')
}

func stripLineComment(line string, marker byte) string {
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			continue
		}
		if ch == marker {
			return line[:i]
		}
	}
	return line
}

func normalizePath(path string) string {
	return filepath.ToSlash(filepath.Clean(filepath.ToSlash(path)))
}

func isRelevantFile(path string) bool {
	if strings.EqualFold(filepath.Base(path), "SKILL.md") {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}
