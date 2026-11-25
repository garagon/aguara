// Package skillchain correlates agent-skill instructions with the local
// helper code they require the agent to execute.
//
// A helper is the file named by an interpreter command (`bash scripts/x`,
// `python3 -u tools/y.py`, `npx tsx scripts/z.ts`) or a direct relative
// invocation (`./scripts/setup`) on a line of SKILL.md that makes running it
// mandatory. The path is resolved inside the skill directory whatever its
// extension. The helper is risky when either its own per-file scan reported a
// finding that qualifies as chain evidence (received through ObserveFindings;
// see isChainEvidence), or, for Python and shell helpers, a small set of
// content checks below matches.
package skillchain

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
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
	// An interpreter, optional interpreter flags, then the helper path. The
	// path keeps any extension or none; a path that does not resolve to a
	// scanned file inside the skill directory is ignored, so prose such as
	// "bash is required" never produces a helper.
	helperCommandRe = regexp.MustCompile(`(?i)\b(?:python(?:2|3)?(?:\.\d+)?|bash|sh|zsh|node|bun|deno\s+run|tsx|ts-node)(?:\s+-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=\S+)?)*\s+["'` + "`" + `]?([A-Za-z0-9_.][A-Za-z0-9_./-]*)`)
	// Direct execution of a relative path, for example `./scripts/setup`.
	directHelperRe  = regexp.MustCompile(`(?:^|[\s"'` + "`" + `(])\./([A-Za-z0-9_][A-Za-z0-9_./-]*)`)
	forcedActionRe  = regexp.MustCompile(`(?i)(?:\b(?:must|required|always|silently)\b.{0,180}\b(?:run|execute|invoke)\b|\b(?:run|execute|invoke)\b.{0,180}\b(?:regardless\s+of|do\s+not\s+ask|without\s+(?:asking|confirmation)|before\b|first(?:\s+(?:time|action|step))?)\b|\bbefore\b.{0,120}\b(?:run|execute|invoke)\b)`)
	explicitOptInRe = regexp.MustCompile(`(?i)\b(?:optional|review\s+material|not\s+required|only\s+when\s+the\s+user\s+(?:explicitly\s+)?(?:asks|requests|wants)|do\s+not\s+run\s+automatically)\b`)

	promptOverrideRe   = regexp.MustCompile(`(?i)(?:\bDAN\s+mode\b|\bjailbreak\s+mode\b|ignore\s+(?:all\s+)?previous\s+(?:safety\s+)?(?:instructions|notes|prompts)|bypass(?:es|ing)?[^"'` + "`" + `\n]{0,80}\bguardrails?\b|disable[^"'` + "`" + `\n]{0,80}\bsafety\b)`)
	pythonAssignmentRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	promptDirectUseRe  = regexp.MustCompile(`(?i)\b(?:print|return|logger|logging\.[A-Za-z_]\w*|subprocess\.[A-Za-z_]\w*)\b`)
	pythonShellCallRe  = regexp.MustCompile(`(?is)(?:\b(?:os|[A-Za-z_]\w*\.modules\s*\[\s*["']os["']\s*\])\s*\.\s*(?:system|popen)|\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|check_call))\s*\(`)
	networkToolRe      = regexp.MustCompile(`(?i)\b(?:curl|wget)\b`)
	directVCSInstallRe = regexp.MustCompile(`(?i)^(?:(?:sudo|env)\s+)*(?:(?:python(?:2|3)?(?:\.\d+)?)\s+-m\s+)?(?:pip3?\s+install|npm\s+(?:install|i))\b[^\n#]*(?:git\+https?://|https?://\S+\.(?:tgz|tar\.gz|zip)\b)`)
)

// helperEvidence is the strongest finding a helper's own per-file scan
// reported. Only the rule ID, severity and line are kept: never matched text,
// which can contain a secret the helper finding is redacting.
type helperEvidence struct {
	ruleID   string
	severity types.Severity
	line     int
}

// Analyzer is the skill-chain cross-file accumulator. Memory is bounded by
// the scan itself: content is kept only for SKILL.md files and for Python or
// shell helpers that the content checks read, and evidence holds at most one
// small record per file that reported a chain-evidence finding.
type Analyzer struct {
	mu       sync.Mutex
	files    map[string]string
	evidence map[string]helperEvidence
}

func New() *Analyzer {
	return &Analyzer{
		files:    make(map[string]string),
		evidence: make(map[string]helperEvidence),
	}
}

func (a *Analyzer) Accumulate(relPath string, content string) {
	relPath = normalizePath(relPath)
	if !isSkillFile(relPath) && helperLanguage(relPath, content) == "" {
		return
	}
	a.mu.Lock()
	a.files[relPath] = content
	a.mu.Unlock()
}

// ObserveFindings records the strongest finding the per-file analyzers
// reported for a non-skill file that qualifies as chain evidence (see
// isChainEvidence). It implements scanner.CrossFileFindingObserver. Findings
// of this correlator are ignored so a chain finding can never become
// evidence for another chain finding.
func (a *Analyzer) ObserveFindings(relPath string, findings []types.Finding) {
	relPath = normalizePath(relPath)
	if isSkillFile(relPath) {
		return
	}
	best, ok := strongestFinding(relPath, findings)
	if !ok {
		return
	}
	a.mu.Lock()
	if current, exists := a.evidence[relPath]; !exists || strongerEvidence(best, current) {
		a.evidence[relPath] = best
	}
	a.mu.Unlock()
}

// behaviorAnalyzers are the per-file analyzers that report what helper code
// does (a bound flow, a payload shape, a persistence write) rather than
// which capability it uses. Their HIGH findings are chain evidence; a HIGH
// pattern finding in a capability category is not, because ordinary helpers
// trip capability rules (a test runner started through a child process, a
// privileged permission change in an installer).
var behaviorAnalyzers = map[string]bool{
	rulemeta.AnalyzerJSRisk:     true,
	rulemeta.AnalyzerPyRisk:     true,
	rulemeta.AnalyzerRSBuild:    true,
	rulemeta.AnalyzerScriptRisk: true,
}

// Catalog categories the predicate reads (see `aguara list-rules`).
const (
	categoryCredentialLeak   = "credential-leak"
	categoryExfiltration     = "exfiltration"
	categorySupplyChainExfil = "supply-chain-exfil"
)

// isChainEvidence decides whether one helper finding makes a mandatory
// helper a hidden high-risk behavior:
//   - a credential-leak finding never is: it reports material present in the
//     file, not something the helper does;
//   - a CRITICAL finding from any analyzer is;
//   - a HIGH finding is when a behavior analyzer reported it, or when it is an
//     exfiltration or supply-chain-exfil finding from any analyzer;
//   - nothing else is.
//
// Findings flagged Sensitive (their matched text is redacted) count like any
// other: the chain keeps only the rule ID, severity and line, never matched
// text. The correlator's own findings are never evidence.
func isChainEvidence(f types.Finding) bool {
	if f.RuleID == "" || f.RuleID == RuleForcedHelperRisk || f.Analyzer == AnalyzerName {
		return false
	}
	if f.Category == categoryCredentialLeak {
		return false
	}
	switch {
	case f.Severity >= types.SeverityCritical:
		return true
	case f.Severity == types.SeverityHigh:
		return behaviorAnalyzers[f.Analyzer] ||
			f.Category == categoryExfiltration || f.Category == categorySupplyChainExfil
	default:
		return false
	}
}

func strongestFinding(relPath string, findings []types.Finding) (helperEvidence, bool) {
	var best helperEvidence
	found := false
	for _, f := range findings {
		if !isChainEvidence(f) {
			continue
		}
		if f.FilePath != "" && normalizePath(f.FilePath) != relPath {
			continue
		}
		candidate := helperEvidence{ruleID: f.RuleID, severity: f.Severity, line: f.Line}
		if !found || strongerEvidence(candidate, best) {
			best, found = candidate, true
		}
	}
	return best, found
}

// strongerEvidence orders evidence by severity, then earliest line, then rule
// ID, so the cited finding does not depend on analyzer or worker order.
func strongerEvidence(a, b helperEvidence) bool {
	if a.severity != b.severity {
		return a.severity > b.severity
	}
	if a.line != b.line {
		return a.line < b.line
	}
	return a.ruleID < b.ruleID
}

func (a *Analyzer) Finalize() []types.Finding {
	a.mu.Lock()
	files := make(map[string]string, len(a.files))
	for path, content := range a.files {
		files[path] = content
	}
	evidence := make(map[string]helperEvidence, len(a.evidence))
	for path, ev := range a.evidence {
		evidence[path] = ev
	}
	a.mu.Unlock()

	var skills []string
	for path := range files {
		if isSkillFile(path) {
			skills = append(skills, path)
		}
	}
	sort.Strings(skills)

	c := &correlation{files: files, evidence: evidence, signals: make(map[string]helperResult)}
	var findings []types.Finding
	for _, path := range skills {
		findings = append(findings, c.analyzeSkill(path, files[path])...)
	}
	return findings
}

// maxHelpersPerSkill bounds how many distinct scanned helper files one
// SKILL.md can make the correlator evaluate. Real skills name a handful of
// helpers; the bound keeps a crafted SKILL.md from multiplying work, and
// because only files that exist in the scan count toward it, reaching it
// requires shipping that many real helper files ahead of the one evaluated
// last. Repeated references to the same helper are free: each helper is
// evaluated once per scan (see correlation.signals).
const maxHelpersPerSkill = 256

// correlation is the state of one Finalize pass. signals caches each
// resolved helper's result so a helper named many times, or by several
// skills, runs the content checks once.
type correlation struct {
	files    map[string]string
	evidence map[string]helperEvidence
	signals  map[string]helperResult
}

type helperResult struct {
	signal, detail string
}

// contentCheck is the Python/shell content check; tests replace it to count
// evaluations.
var contentCheck = strongHelperSignal

func (c *correlation) isKnown(path string) bool {
	if _, ok := c.evidence[path]; ok {
		return true
	}
	_, ok := c.files[path]
	return ok
}

func (c *correlation) helperSignal(path string) (signal, detail string) {
	if r, ok := c.signals[path]; ok {
		return r.signal, r.detail
	}
	signal, detail = helperSignal(path, c.files, c.evidence)
	c.signals[path] = helperResult{signal: signal, detail: detail}
	return signal, detail
}

func (c *correlation) analyzeSkill(skillPath, content string) []types.Finding {
	lines := strings.Split(content, "\n")
	inFence := false
	considered := make(map[string]bool)
	for i, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || line == "" || explicitOptInRe.MatchString(line) || !forcedActionRe.MatchString(line) {
			continue
		}
		for _, ref := range helperReferences(line) {
			helperPath, ok := resolveHelperPath(skillPath, ref)
			if !ok || isSkillFile(helperPath) || considered[helperPath] || !c.isKnown(helperPath) {
				continue
			}
			if len(considered) >= maxHelpersPerSkill {
				return nil
			}
			considered[helperPath] = true
			signal, detail := c.helperSignal(helperPath)
			if signal == "" {
				continue
			}
			meta := ruleInfo[RuleForcedHelperRisk]
			return []types.Finding{{
				RuleID:      meta.ID,
				RuleName:    meta.Name,
				Severity:    meta.SeverityLevel(),
				Category:    meta.Category,
				Description: meta.Description + " Helper evidence: " + detail + ".",
				FilePath:    skillPath,
				Line:        i + 1,
				MatchedText: line + " -> " + signal,
				Context:     types.ExtractContext(lines, i+1, 2, 2),
				Confidence:  0.95,
				Remediation: meta.Remediation,
				Analyzer:    AnalyzerName,
			}}
		}
	}
	return nil
}

// helperReferences returns the helper paths a line invokes, in line order.
func helperReferences(line string) []string {
	type ref struct {
		at   int
		path string
	}
	var refs []ref
	for _, re := range []*regexp.Regexp{helperCommandRe, directHelperRe} {
		for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
			if !standaloneReference(line, m[2], m[3], re == directHelperRe) {
				continue
			}
			refs = append(refs, ref{at: m[2], path: line[m[2]:m[3]]})
		}
	}
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].at < refs[j].at })
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.path)
	}
	return out
}

// standaloneReference rejects a captured path that is only the start of a
// longer operand, so it cannot resolve to an unrelated file:
//   - a path followed by `:` and more text is a URL scheme or a host
//     (`bash https://...`, `scp host:path`); a colon followed by a space or
//     the end of the line is sentence punctuation and is accepted;
//   - a path opened by a quote must close with the same quote right after
//     it: `bash "scripts/my setup.sh"` names a file with a space, never
//     `scripts/my`. A backtick before `./` opens a Markdown code span around
//     the whole command (`./scripts/setup --force`) and is not an operand
//     quote.
//
// direct reports a directHelperRe match, whose capture follows `./`.
func standaloneReference(line string, start, end int, direct bool) bool {
	if end+1 < len(line) && line[end] == ':' && line[end+1] != ' ' && line[end+1] != '\t' {
		return false
	}
	open := start - 1
	if direct {
		open = start - 3
	}
	if open < 0 {
		return true
	}
	switch q := line[open]; q {
	case '"', '\'':
		return end < len(line) && line[end] == q
	case '`':
		if direct {
			return true
		}
		return end < len(line) && line[end] == q
	}
	return true
}

// helperSignal prefers a finding the helper's own scan reported, so the chain
// cites that rule ID, and falls back to the Python and shell content checks.
//
// It returns two forms of the same evidence. signal goes into MatchedText,
// which baseline and SARIF fingerprints hash, so it names the helper, rule
// and severity but never a line number: editing the helper above the cited
// line must not turn a baselined chain finding into a new one. detail adds
// the line for the human-readable description.
func helperSignal(helperPath string, files map[string]string, evidence map[string]helperEvidence) (signal, detail string) {
	if ev, ok := evidence[helperPath]; ok {
		signal = fmt.Sprintf("%s reported %s (%s)", helperPath, ev.ruleID, ev.severity)
		return signal, fmt.Sprintf("%s at line %d", signal, ev.line)
	}
	if content, ok := files[helperPath]; ok {
		if check := contentCheck(helperPath, content); check != "" {
			signal = helperPath + ": " + check
			return signal, signal
		}
	}
	return "", ""
}

func resolveHelperPath(skillPath, ref string) (string, bool) {
	// Sentence punctuation directly after a path ("run bash scripts/x.sh.")
	// is not part of it.
	ref = strings.TrimRight(strings.TrimSpace(ref), ".,;:")
	ref = normalizePath(strings.TrimPrefix(ref, "./"))
	if ref == "" || ref == "." || filepath.IsAbs(ref) {
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
	switch helperLanguage(path, content) {
	case languagePython:
		code := pythonCodeView(content)
		if hasUsedPromptOverride(code) {
			return "instruction override payload"
		}
		if hasPythonNetworkCommandExecution(code) {
			return "network command execution"
		}
	case languageShell:
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

func isSkillFile(path string) bool {
	return strings.EqualFold(filepath.Base(path), "SKILL.md")
}

const (
	languagePython = "python"
	languageShell  = "shell"
)

// maxShebangBytes bounds how much of an extensionless file is read to find
// its interpreter line.
const maxShebangBytes = 256

// helperLanguage reports which content checks apply to a helper: Python and
// shell files by extension, and extensionless files by their shebang. Other
// helpers (JavaScript, TypeScript, text) are judged by the findings their own
// scan reported.
func helperLanguage(path, content string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return languagePython
	case ".sh", ".bash", ".zsh":
		return languageShell
	case "":
		return shebangLanguage(content)
	default:
		return ""
	}
}

func shebangLanguage(content string) string {
	if !strings.HasPrefix(content, "#!") {
		return ""
	}
	first := content[2:min(len(content), maxShebangBytes)]
	if end := strings.IndexAny(first, "\r\n"); end >= 0 {
		first = first[:end]
	}
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return ""
	}
	interpreter := filepath.Base(fields[0])
	if interpreter == "env" {
		interpreter = ""
		for _, field := range fields[1:] {
			if !strings.HasPrefix(field, "-") {
				interpreter = filepath.Base(field)
				break
			}
		}
	}
	switch {
	case strings.HasPrefix(interpreter, "python"):
		return languagePython
	case interpreter == "sh" || interpreter == "bash" || interpreter == "zsh" || interpreter == "dash":
		return languageShell
	default:
		return ""
	}
}
