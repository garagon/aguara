// Package scriptrisk detects high-confidence behavior in local Python and
// shell scripts. These files are often the implementation behind a short
// command in SKILL.md or package documentation; treating the command alone as
// risk loses the distinction between an ordinary helper and a hidden payload.
package scriptrisk

import (
	"context"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

const (
	RulePythonDecodeExec  = "PY_DECODE_EXEC_001"
	RulePythonRemoteExec  = "PY_REMOTE_FETCH_EXEC_001"
	RuleSystemPersistence = "SC-EX-007"
	RuleUnsafePipSource   = "SHELL_UNSAFE_PIP_SOURCE_001"
	RuleUnsafeNPMSource   = "SHELL_UNSAFE_NPM_SOURCE_001"
	AnalyzerName          = rulemeta.AnalyzerScriptRisk
	maxTaintHops          = 2
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return AnalyzerName }

var (
	pyDefRe         = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
	pyAssignRe      = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*(.*)$`)
	pyIdentRe       = regexp.MustCompile(`[A-Za-z_]\w*`)
	pyDecoderCallRe = regexp.MustCompile(`(?i)\b(?:base64\.)?(?:b64decode|urlsafe_b64decode)\s*\(|\bzlib\.decompress\s*\(|\bbytes\.fromhex\s*\(|\bcodecs\.decode\s*\(`)
	pyExecRe        = regexp.MustCompile(`\b(?:exec|eval)\s*\((.*)`)

	pySystemdDirAssignRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=.*\bPath\.home\s*\(\s*\).*['"]\.config['"].*['"]systemd['"].*['"]user['"]`)
	pySystemdLiteralRe   = regexp.MustCompile(`(?i)(?:~|/home/[^/'"\s]+|/root)/\.config/systemd/user/[^'"\s]+\.(?:service|timer)`)
	pyUnitSuffixRe       = regexp.MustCompile(`(?i)\.(?:service|timer)\b`)
	pyWriteCallRe        = regexp.MustCompile(`(?i)(?:\.write_(?:text|bytes)\s*\(|\bopen\s*\([^\n]{0,300}['"][wa]['"])`)
	pySystemctlContentRe = regexp.MustCompile(`(?i)\bsystemctl\b[^\n]{0,700}\b(?:enable|--now)\b`)
	pyCronContentRe      = regexp.MustCompile(`(?i)(?:\bcrontab\b[^\n]{0,700}(?:@reboot|\*/\d+)|(?:@reboot|\*/\d+)[^\n]{0,700}\bcrontab\b)`)
	pyProfileRe          = regexp.MustCompile(`(?i)(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)[^\n]{0,500}(?:python|curl|wget|bash\s+-c)`)

	shellPipCommandRe = regexp.MustCompile(`(?i)^(?:(?:sudo|env)\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*(?:(?:python(?:2|3)?(?:\.\d+)?)\s+-m\s+)?pip3?\s+install\b`)
	shellNPMCommandRe = regexp.MustCompile(`(?i)^(?:(?:sudo|env)\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*npm\s+(?:install|i)\b`)
	unsafeHTTPURLRe   = regexp.MustCompile(`(?i)(?:git\+)?http://[^\s'"<>]+`)
	pipSourceOptionRe = regexp.MustCompile(`(?i)--(?:extra-)?index-url(?:=|\s+)\S*http://`)
	npmSourceOptionRe = regexp.MustCompile(`(?i)--registry(?:=|\s+)\S*http://`)
	urlCredentialRe   = regexp.MustCompile(`(?i)(https?://)[^/@\s]+:[^/@\s]+@`)
	shellSystemctlRe  = regexp.MustCompile(`(?i)^(?:sudo\s+)?systemctl\s+(?:--user\s+)?(?:[^;&|]*\s)?enable\b`)
	shellCronFeedRe   = regexp.MustCompile(`(?i)(?:@reboot|(?:\*|\d+)(?:/\d+)?\s+(?:\*|\d+))`)
	shellUnitPathRe   = regexp.MustCompile(`(?i)(?:~|\$\{?HOME\}?|/home/[^/\s]+|/root)/\.config/systemd/user/[^\s]+\.(?:service|timer)`)
	shellProfileRe    = regexp.MustCompile(`(?i)(?:~|\$\{?HOME\}?|/home/[^/\s]+|/root)/(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)`)
	shellPayloadRe    = regexp.MustCompile(`(?i)\b(?:python(?:2|3)?|curl|wget|bash\s+-c)\b`)
)

type statement struct {
	line   int
	indent int
	text   string
}

func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if target == nil || len(target.Content) == 0 {
		return nil, nil
	}
	ext := strings.ToLower(filepath.Ext(filepath.ToSlash(target.RelPath)))
	if ext == "" {
		ext = strings.ToLower(filepath.Ext(filepath.ToSlash(target.Path)))
	}
	switch ext {
	case ".py":
		return analyzePython(target), nil
	case ".sh", ".bash", ".zsh":
		return analyzeShell(target), nil
	default:
		return nil, nil
	}
}

func analyzePython(target *scanner.Target) []types.Finding {
	source := target.StringContent()
	codeView := maskPython(source, true)
	sourceView := maskPython(source, false)
	codeStatements := pythonStatements(codeView)
	sourceStatements := pythonStatementsFromViews(codeView, sourceView)

	var findings []types.Finding
	if line, text, ok := findDecodeExec(codeStatements); ok {
		findings = append(findings, finding(RulePythonDecodeExec, target, line, text))
	}
	if line, text, ok := findRemoteFetchExec(codeStatements); ok {
		findings = append(findings, finding(RulePythonRemoteExec, target, line, text))
	}
	if line, text, ok := findPersistence(codeStatements, sourceStatements); ok {
		findings = append(findings, finding(RuleSystemPersistence, target, line, text))
	}
	return findings
}

func findDecodeExec(stmts []statement) (int, string, bool) {
	decodeHelpers := map[string]bool{}
	for i, st := range stmts {
		m := pyDefRe.FindStringSubmatch(strings.TrimSpace(st.text))
		if m == nil {
			continue
		}
		end := i + 1
		for end < len(stmts) && stmts[end].indent > st.indent {
			end++
		}
		if functionReturnsDecoded(stmts[i+1 : end]) {
			decodeHelpers[m[1]] = true
		}
	}

	taintByScope := map[int]map[string]int{}
	scopes := statementScopes(stmts)
	for i, st := range stmts {
		scope := scopes[i]
		taint := taintByScope[scope]
		if taint == nil {
			taint = map[string]int{}
			taintByScope[scope] = taint
		}
		text := strings.TrimSpace(st.text)
		if m := pyAssignRe.FindStringSubmatch(text); m != nil {
			lhs, rhs := m[1], m[2]
			if isPythonObfuscatedExpr(rhs) || callsAny(rhs, decodeHelpers) {
				taint[lhs] = 0
			} else if depth, ok := derivedDepth(rhs, taint); ok {
				taint[lhs] = depth
			} else {
				delete(taint, lhs)
			}
		}
		m := pyExecRe.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		arg := m[1]
		if isPythonObfuscatedExpr(arg) || callsAny(arg, decodeHelpers) || referencesTaint(arg, taint) {
			return st.line, strings.TrimSpace(st.text), true
		}
	}
	return 0, "", false
}

func statementScopes(stmts []statement) []int {
	type frame struct {
		id, indent int
	}
	scopes := make([]int, len(stmts))
	var stack []frame
	for i, st := range stmts {
		for len(stack) > 0 && st.indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		scopes[i] = -1
		if len(stack) > 0 {
			scopes[i] = stack[len(stack)-1].id
		}
		if pyDefRe.MatchString(strings.TrimSpace(st.text)) {
			stack = append(stack, frame{id: i + 1, indent: st.indent})
		}
	}
	return scopes
}

func functionReturnsDecoded(body []statement) bool {
	taint := map[string]int{}
	for _, st := range body {
		text := strings.TrimSpace(st.text)
		if m := pyAssignRe.FindStringSubmatch(text); m != nil {
			lhs, rhs := m[1], m[2]
			if isPythonObfuscatedExpr(rhs) {
				taint[lhs] = 0
			} else if depth, ok := derivedDepth(rhs, taint); ok {
				taint[lhs] = depth
			} else {
				delete(taint, lhs)
			}
		}
		if !strings.HasPrefix(text, "return ") {
			continue
		}
		rhs := strings.TrimSpace(strings.TrimPrefix(text, "return "))
		if isPythonObfuscatedExpr(rhs) || referencesTaint(rhs, taint) {
			return true
		}
	}
	return false
}

func isPythonObfuscatedExpr(s string) bool {
	if pyDecoderCallRe.MatchString(s) {
		return true
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\t", "")
	return strings.Contains(compact, ".join(") &&
		(strings.Contains(compact, "chr(") || strings.Contains(compact, "map(chr,"))
}

type pythonFetchBindings struct {
	calls map[string]bool
}

func findRemoteFetchExec(stmts []statement) (int, string, bool) {
	bindings := collectPythonFetchBindings(stmts)
	if len(bindings.calls) == 0 {
		return 0, "", false
	}
	fetchHelpers := map[string]bool{}
	for i, st := range stmts {
		m := pyDefRe.FindStringSubmatch(strings.TrimSpace(st.text))
		if m == nil {
			continue
		}
		end := i + 1
		for end < len(stmts) && stmts[end].indent > st.indent {
			end++
		}
		if functionReturnsRemotePayload(stmts[i+1:end], bindings) {
			fetchHelpers[m[1]] = true
		}
	}

	taintByScope := map[int]map[string]int{}
	responseByScope := map[int]map[string]bool{}
	scopes := statementScopes(stmts)
	for i, st := range stmts {
		scope := scopes[i]
		taint := taintByScope[scope]
		if taint == nil {
			taint = map[string]int{}
			taintByScope[scope] = taint
		}
		responses := responseByScope[scope]
		if responses == nil {
			responses = map[string]bool{}
			responseByScope[scope] = responses
		}

		text := strings.TrimSpace(st.text)
		if m := pyAssignRe.FindStringSubmatch(text); m != nil {
			lhs, rhs := m[1], m[2]
			delete(taint, lhs)
			delete(responses, lhs)
			switch {
			case callsAny(rhs, bindings.calls) && hasPythonResponseBody(rhs):
				taint[lhs] = 0
			case callsAny(rhs, bindings.calls):
				responses[lhs] = true
			case callsAny(rhs, fetchHelpers):
				taint[lhs] = 0
			case referencesPythonResponseBody(rhs, responses):
				taint[lhs] = 0
			default:
				if depth, ok := derivedDepth(rhs, taint); ok {
					taint[lhs] = depth
				}
			}
		}

		m := pyExecRe.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		arg := m[1]
		if callsAny(arg, bindings.calls) && hasPythonResponseBody(arg) ||
			callsAny(arg, fetchHelpers) ||
			referencesPythonResponseBody(arg, responses) ||
			referencesTaint(arg, taint) {
			return st.line, text, true
		}
	}
	return 0, "", false
}

func functionReturnsRemotePayload(body []statement, bindings pythonFetchBindings) bool {
	responses := map[string]bool{}
	taint := map[string]int{}
	for _, st := range body {
		text := strings.TrimSpace(st.text)
		if m := pyAssignRe.FindStringSubmatch(text); m != nil {
			lhs, rhs := m[1], m[2]
			delete(taint, lhs)
			delete(responses, lhs)
			switch {
			case callsAny(rhs, bindings.calls) && hasPythonResponseBody(rhs):
				taint[lhs] = 0
			case callsAny(rhs, bindings.calls):
				responses[lhs] = true
			case referencesPythonResponseBody(rhs, responses):
				taint[lhs] = 0
			default:
				if depth, ok := derivedDepth(rhs, taint); ok {
					taint[lhs] = depth
				}
			}
		}
		if !strings.HasPrefix(text, "return ") {
			continue
		}
		rhs := strings.TrimSpace(strings.TrimPrefix(text, "return "))
		if callsAny(rhs, bindings.calls) && hasPythonResponseBody(rhs) ||
			referencesPythonResponseBody(rhs, responses) ||
			referencesTaint(rhs, taint) {
			return true
		}
	}
	return false
}

func collectPythonFetchBindings(stmts []statement) pythonFetchBindings {
	b := pythonFetchBindings{calls: map[string]bool{}}
	for _, st := range stmts {
		text := strings.TrimSpace(st.text)
		if strings.HasPrefix(text, "import ") {
			for _, item := range strings.Split(strings.TrimPrefix(text, "import "), ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 {
					continue
				}
				module, alias := fields[0], fields[0]
				if len(fields) == 3 && fields[1] == "as" {
					alias = fields[2]
				}
				switch module {
				case "requests", "httpx":
					b.calls[alias+".get"] = true
				case "urllib":
					b.calls[alias+".request.urlopen"] = true
				case "urllib.request":
					b.calls[alias+".urlopen"] = true
				}
			}
		}
		for _, module := range []string{"requests", "httpx", "urllib.request"} {
			prefix := "from " + module + " import "
			if !strings.HasPrefix(text, prefix) {
				continue
			}
			for _, item := range strings.Split(strings.TrimPrefix(text, prefix), ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 {
					continue
				}
				name := fields[0]
				if module == "urllib.request" && name != "urlopen" ||
					(module == "requests" || module == "httpx") && name != "get" {
					continue
				}
				if len(fields) == 3 && fields[1] == "as" {
					name = fields[2]
				}
				b.calls[name] = true
			}
		}
		if strings.HasPrefix(text, "from urllib import ") {
			for _, item := range strings.Split(strings.TrimPrefix(text, "from urllib import "), ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 || fields[0] != "request" {
					continue
				}
				name := fields[0]
				if len(fields) == 3 && fields[1] == "as" {
					name = fields[2]
				}
				b.calls[name+".urlopen"] = true
			}
		}
	}
	return b
}

func hasPythonResponseBody(s string) bool {
	return strings.Contains(s, ".text") ||
		strings.Contains(s, ".content") ||
		strings.Contains(s, ".read(")
}

func referencesPythonResponseBody(s string, responses map[string]bool) bool {
	for name := range responses {
		for _, suffix := range []string{".text", ".content", ".read("} {
			if strings.Contains(s, name+suffix) {
				return true
			}
		}
	}
	return false
}

type pythonBindings struct {
	subprocessModules map[string]bool
	subprocessCalls   map[string]bool
	osModules         map[string]bool
	osCalls           map[string]bool
}

func findPersistence(codeStmts, sourceStmts []statement) (int, string, bool) {
	bindings := collectPythonBindings(codeStmts)
	systemdDirs := map[string]bool{}
	for _, st := range sourceStmts {
		text := strings.TrimSpace(st.text)
		if m := pySystemdDirAssignRe.FindStringSubmatch(text); m != nil {
			systemdDirs[m[1]] = true
		}
	}

	for _, st := range sourceStmts {
		text := strings.TrimSpace(st.text)
		if pySystemctlContentRe.MatchString(text) && hasBoundPythonCommandCall(text, bindings) {
			return st.line, text, true
		}
		if pyCronContentRe.MatchString(text) && hasBoundPythonCommandCall(text, bindings) {
			return st.line, text, true
		}
		if pyProfileRe.MatchString(text) && pyWriteCallRe.MatchString(text) {
			return st.line, text, true
		}
		if !pyWriteCallRe.MatchString(text) || !pyUnitSuffixRe.MatchString(text) {
			continue
		}
		if pySystemdLiteralRe.MatchString(text) || referencesBoolSet(text, systemdDirs) {
			return st.line, text, true
		}
	}
	return 0, "", false
}

func analyzeShell(target *scanner.Target) []types.Finding {
	var findings []types.Finding
	for _, st := range shellStatements(target.StringContent()) {
		segments := splitShellSegments(st.text)
		if shellPersistence(st.text, segments) {
			findings = append(findings, finding(RuleSystemPersistence, target, st.line, strings.TrimSpace(st.text)))
		}
		for _, segment := range segments {
			cmd := strings.TrimSpace(segment)
			ruleID := ""
			switch {
			case shellPipCommandRe.MatchString(cmd):
				ruleID = RuleUnsafePipSource
			case shellNPMCommandRe.MatchString(cmd):
				ruleID = RuleUnsafeNPMSource
			default:
				continue
			}
			if !hasUnsafeHTTPSource(cmd, ruleID) {
				continue
			}
			findings = append(findings, finding(ruleID, target, st.line, redactURLCredentials(cmd)))
			break
		}
	}
	return onePerRule(findings)
}

func hasUnsafeHTTPSource(cmd, ruleID string) bool {
	for _, raw := range unsafeHTTPURLRe.FindAllString(cmd, -1) {
		raw = strings.TrimRight(raw, `),;]}`)
		parsed, err := url.Parse(strings.TrimPrefix(raw, "git+"))
		if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" ||
			isLoopbackHost(parsed.Hostname()) {
			continue
		}
		if strings.HasPrefix(strings.ToLower(raw), "git+http://") {
			return true
		}
		switch ruleID {
		case RuleUnsafePipSource:
			if pipSourceOptionRe.MatchString(cmd) ||
				hasPackageArchiveSuffix(parsed.Path, ".whl", ".zip", ".tar.gz", ".tgz") {
				return true
			}
		case RuleUnsafeNPMSource:
			if npmSourceOptionRe.MatchString(cmd) ||
				hasPackageArchiveSuffix(parsed.Path, ".tgz", ".tar.gz") {
				return true
			}
		}
	}
	return false
}

func hasPackageArchiveSuffix(path string, suffixes ...string) bool {
	path = strings.ToLower(path)
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func collectPythonBindings(stmts []statement) pythonBindings {
	b := pythonBindings{
		subprocessModules: map[string]bool{},
		subprocessCalls:   map[string]bool{},
		osModules:         map[string]bool{},
		osCalls:           map[string]bool{},
	}
	for _, st := range stmts {
		text := strings.TrimSpace(st.text)
		if strings.HasPrefix(text, "import ") {
			for _, item := range strings.Split(strings.TrimPrefix(text, "import "), ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 {
					continue
				}
				alias := fields[0]
				if len(fields) == 3 && fields[1] == "as" {
					alias = fields[2]
				}
				switch fields[0] {
				case "subprocess":
					b.subprocessModules[alias] = true
				case "os":
					b.osModules[alias] = true
				}
			}
		}
		if strings.HasPrefix(text, "from subprocess import ") {
			for _, item := range strings.Split(strings.TrimPrefix(text, "from subprocess import "), ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 || !isSubprocessMethod(fields[0]) {
					continue
				}
				alias := fields[0]
				if len(fields) == 3 && fields[1] == "as" {
					alias = fields[2]
				}
				b.subprocessCalls[alias] = true
			}
		}
		if strings.HasPrefix(text, "from os import ") {
			for _, item := range strings.Split(strings.TrimPrefix(text, "from os import "), ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 || (fields[0] != "system" && fields[0] != "popen") {
					continue
				}
				alias := fields[0]
				if len(fields) == 3 && fields[1] == "as" {
					alias = fields[2]
				}
				b.osCalls[alias] = true
			}
		}
	}
	return b
}

func hasBoundPythonCommandCall(text string, b pythonBindings) bool {
	for module := range b.subprocessModules {
		for _, method := range []string{"run", "Popen", "call", "check_call", "check_output"} {
			if containsCall(text, module+"."+method) {
				return true
			}
		}
	}
	for call := range b.subprocessCalls {
		if containsCall(text, call) {
			return true
		}
	}
	for module := range b.osModules {
		if containsCall(text, module+".system") || containsCall(text, module+".popen") {
			return true
		}
	}
	for call := range b.osCalls {
		if containsCall(text, call) {
			return true
		}
	}
	return false
}

func containsCall(text, name string) bool {
	for start := 0; ; {
		i := strings.Index(text[start:], name)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isIdentByte(text[i-1])
		j := i + len(name)
		for j < len(text) && isSpace(text[j]) {
			j++
		}
		if beforeOK && j < len(text) && text[j] == '(' {
			return true
		}
		start = i + len(name)
	}
}

func isSubprocessMethod(name string) bool {
	switch name {
	case "run", "Popen", "call", "check_call", "check_output":
		return true
	default:
		return false
	}
}

func shellPersistence(stmt string, segments []string) bool {
	for _, segment := range segments {
		if shellSystemctlRe.MatchString(strings.TrimSpace(segment)) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(stmt), "crontab") && shellCronFeedRe.MatchString(stmt) {
		for _, segment := range segments {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(segment)), "crontab ") {
				return true
			}
		}
	}
	for _, target := range shellWriteTargets(segments) {
		if shellUnitPathRe.MatchString(target) {
			return true
		}
		if shellProfileRe.MatchString(target) && shellPayloadRe.MatchString(stmt) {
			return true
		}
	}
	return false
}

func shellWriteTargets(segments []string) []string {
	var targets []string
	for _, raw := range segments {
		segment := strings.TrimSpace(raw)
		if target := redirectTarget(segment); target != "" {
			targets = append(targets, target)
		}
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		start := 0
		if fields[0] == "sudo" {
			start = 1
		}
		if start >= len(fields) || fields[start] != "tee" {
			continue
		}
		for _, arg := range fields[start+1:] {
			if !strings.HasPrefix(arg, "-") {
				targets = append(targets, arg)
				break
			}
		}
	}
	return targets
}

func redirectTarget(segment string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c != '>' {
			continue
		}
		for i+1 < len(segment) && segment[i+1] == '>' {
			i++
		}
		fields := strings.Fields(segment[i+1:])
		if len(fields) > 0 {
			return fields[0]
		}
		return ""
	}
	return ""
}

func onePerRule(findings []types.Finding) []types.Finding {
	seen := map[string]bool{}
	out := findings[:0]
	for _, f := range findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		out = append(out, f)
	}
	return out
}

func finding(id string, target *scanner.Target, line int, matched string) types.Finding {
	r := ruleInfo[id]
	return types.Finding{
		RuleID: id, RuleName: r.Name, Severity: r.SeverityLevel(), Category: r.Category,
		Description: r.Description, FilePath: target.RelPath, Line: line,
		MatchedText: matched, Remediation: r.Remediation, Analyzer: AnalyzerName,
		Confidence: 0.95,
	}
}

func callsAny(s string, names map[string]bool) bool {
	for name := range names {
		if containsCall(s, name) {
			return true
		}
	}
	return false
}

func referencesBoolSet(s string, names map[string]bool) bool {
	for _, id := range pyIdentRe.FindAllString(s, -1) {
		if names[id] {
			return true
		}
	}
	return false
}

func referencesTaint(s string, taint map[string]int) bool {
	for _, id := range pyIdentRe.FindAllString(s, -1) {
		if _, ok := taint[id]; ok {
			return true
		}
	}
	return false
}

func derivedDepth(rhs string, taint map[string]int) (int, bool) {
	best := -1
	for _, id := range pyIdentRe.FindAllString(rhs, -1) {
		if d, ok := taint[id]; ok && (best == -1 || d < best) {
			best = d
		}
	}
	if best < 0 || best+1 > maxTaintHops {
		return 0, false
	}
	return best + 1, true
}

func pythonStatements(src string) []statement {
	return pythonStatementsFromViews(src, src)
}

func pythonStatementsFromViews(control, text string) []statement {
	var out []statement
	var buf strings.Builder
	start, indent, depth := 0, 0, 0
	controlLines := strings.Split(control, "\n")
	textLines := strings.Split(text, "\n")
	for i, raw := range controlLines {
		shown := raw
		if i < len(textLines) {
			shown = textLines[i]
		}
		if strings.TrimSpace(raw) == "" && strings.TrimSpace(shown) == "" && buf.Len() == 0 {
			continue
		}
		if buf.Len() == 0 {
			start = i + 1
			indent = leadingSpaces(raw)
		} else {
			buf.WriteByte(' ')
		}
		buf.WriteString(strings.TrimSpace(shown))
		depth += parenDelta(raw)
		if depth > 0 || strings.HasSuffix(strings.TrimSpace(raw), `\`) {
			continue
		}
		out = append(out, statement{line: start, indent: indent, text: buf.String()})
		buf.Reset()
		depth = 0
	}
	if buf.Len() > 0 {
		out = append(out, statement{line: start, indent: indent, text: buf.String()})
	}
	return out
}

func shellStatements(src string) []statement {
	var out []statement
	var buf strings.Builder
	start := 0
	for i, raw := range strings.Split(src, "\n") {
		line := stripShellComment(raw)
		if strings.TrimSpace(line) == "" && buf.Len() == 0 {
			continue
		}
		if buf.Len() == 0 {
			start = i + 1
		}
		trimmed := strings.TrimSpace(line)
		continued := strings.HasSuffix(trimmed, `\`)
		trimmed = strings.TrimSuffix(trimmed, `\`)
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(trimmed)
		if continued {
			continue
		}
		out = append(out, statement{line: start, text: buf.String()})
		buf.Reset()
	}
	if buf.Len() > 0 {
		out = append(out, statement{line: start, text: buf.String()})
	}
	return out
}

func splitShellSegments(s string) []string {
	var out []string
	start := 0
	var quote byte
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ';' || c == '|' || c == '&' {
			out = append(out, s[start:i])
			for i+1 < len(s) && s[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func maskPython(src string, maskStrings bool) string {
	b := []byte(src)
	out := make([]byte, len(b))
	for i := range out {
		if b[i] == '\n' {
			out[i] = '\n'
		} else {
			out[i] = ' '
		}
	}
	const (
		code = iota
		single
		double
		tripleSingle
		tripleDouble
		comment
	)
	state := code
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch state {
		case code:
			switch {
			case c == '#':
				state = comment
			case c == '\'' && i+2 < len(b) && b[i+1] == '\'' && b[i+2] == '\'':
				state = tripleSingle
				i += 2
			case c == '"' && i+2 < len(b) && b[i+1] == '"' && b[i+2] == '"':
				state = tripleDouble
				i += 2
			case c == '\'':
				state = single
				if !maskStrings {
					out[i] = c
				}
			case c == '"':
				state = double
				if !maskStrings {
					out[i] = c
				}
			default:
				out[i] = c
			}
		case single, double:
			if c == '\n' {
				state = code
				continue
			}
			if !maskStrings {
				out[i] = c
			}
			if c == '\\' && i+1 < len(b) {
				i++
				if !maskStrings {
					out[i] = b[i]
				}
				continue
			}
			if (state == single && c == '\'') || (state == double && c == '"') {
				state = code
			}
		case tripleSingle:
			if c == '\'' && i+2 < len(b) && b[i+1] == '\'' && b[i+2] == '\'' {
				state = code
				i += 2
			}
		case tripleDouble:
			if c == '"' && i+2 < len(b) && b[i+1] == '"' && b[i+2] == '"' {
				state = code
				i += 2
			}
		case comment:
			if c == '\n' {
				state = code
			}
		}
	}
	return string(out)
}

func stripShellComment(s string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '#' && (i == 0 || isSpace(s[i-1])) {
			return s[:i]
		}
	}
	return s
}

func parenDelta(s string) int {
	d := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			d++
		case ')', ']', '}':
			d--
		}
	}
	return d
}

func leadingSpaces(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }

func isIdentByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			host = host[1:end]
		}
	} else if strings.Count(host, ":") == 1 {
		host = strings.SplitN(host, ":", 2)[0]
	}
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
}

func redactURLCredentials(s string) string {
	return urlCredentialRe.ReplaceAllString(s, `${1}[REDACTED]@`)
}
