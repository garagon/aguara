package discover

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/garagon/aguara/internal/types"
)

// redactedPlaceholder replaces a secret in discovery output. It is the placeholder
// scan findings use, so a reader sees that a value was there and removed.
const redactedPlaceholder = types.RedactedPlaceholder

// secretShapes match credential formats the credential-leak rules report:
// provider API keys and tokens, webhook URLs with their secret path, JSON
// Web Tokens and private key headers. A match is replaced wherever it
// appears in a server's command, arguments, URL, headers or environment.
var secretShapes = regexp.MustCompile(strings.Join([]string{
	`sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}`,
	`(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}`,
	`AKIA[0-9A-Z]{16}`,
	`gh[pousr]_[A-Za-z0-9]{20,}`,
	`github_pat_[A-Za-z0-9_]{20,}`,
	`glpat-[A-Za-z0-9_-]{20,}`,
	`xox[abprs]-[A-Za-z0-9-]{10,}`,
	`npm_[A-Za-z0-9]{30,}`,
	`pypi-[A-Za-z0-9_-]{30,}`,
	`AIza[0-9A-Za-z_-]{30,}`,
	`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`,
	`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
	`hooks\.slack\.com/services/[A-Za-z0-9/]+`,
	`(?:discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`,
	`[0-9]{8,10}:[A-Za-z0-9_-]{30,}`, // bot token (id:secret), also inside a URL path
	`-----BEGIN[ A-Z]*PRIVATE KEY(?: BLOCK)?-----`,
}, "|"))

var (
	// uuidSegment is a UUID path segment. Hosted MCP endpoints use one as a
	// per-user or per-workspace capability, so it is redacted.
	uuidSegment = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// tokenSegment is the shape of a path segment that can be a credential.
	tokenSegment = regexp.MustCompile(`^[A-Za-z0-9_=+.~-]{20,}$`)
)

// credentialSegment reports whether a URL path segment looks like a
// credential: a UUID, or 20 or more token characters with both a letter
// and a digit that do not read as a slug or file name made of words and
// numbers (release-notes-2024-final.md, my-server-v2-production).
func credentialSegment(seg string) bool {
	if uuidSegment.MatchString(seg) {
		return true
	}
	if !tokenSegment.MatchString(seg) || !strings.ContainsAny(seg, "0123456789") || !strings.ContainsFunc(seg, unicode.IsLetter) {
		return false
	}
	return !readableSegment(seg)
}

// readableSegment reports whether seg is two or more parts separated by
// "-", "_", "." or "~", each a word or a number of at most 12 characters,
// or a short mixed part such as v2 or x86.
func readableSegment(seg string) bool {
	parts := strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '~' })
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		letters := strings.ContainsFunc(p, unicode.IsLetter)
		digits := strings.ContainsFunc(p, unicode.IsDigit)
		if len(p) > 12 || (letters && digits && len(p) > 4) || strings.ContainsAny(p, "=+") {
			return false
		}
	}
	return true
}

// redactPath replaces the path segments of a URL path that look like
// credentials.
func redactPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if credentialSegment(s) {
			segs[i] = redactedPlaceholder
		}
	}
	return strings.Join(segs, "/")
}

// headerValueNeverSecret lists the headers whose values are shown; every
// other header value is redacted, whatever the header's name.
var headerValueNeverSecret = map[string]bool{
	"accept": true, "content-type": true, "user-agent": true, "mcp-protocol-version": true,
}

// redactHeader returns a header value safe to show.
func redactHeader(name, value string) string {
	if headerValueNeverSecret[strings.ToLower(strings.TrimSpace(name))] {
		return redactValue(value)
	}
	return redactedPlaceholder
}

var (
	// authScheme matches the credential after an HTTP authorization scheme.
	authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=-]{4,}`)
	// queryParam matches one name=value pair of a query outside a URL.
	queryParam = regexp.MustCompile(`([?&])([^=&#\s]+)=([^&#\s]*)`)
	// urlPattern matches a URL with a scheme, up to whitespace or a quote.
	urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	// headerArg matches a "Name: value" header such as the --header value
	// of an MCP proxy.
	headerArg = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$`)
	// assignment matches a NAME=value argument such as the one after
	// docker's -e.
	assignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$`)
	// connSegment matches one Name=value segment of a semicolon-separated
	// connection string.
	connSegment = regexp.MustCompile(`(^|;)(\s*)([A-Za-z][A-Za-z0-9 _.-]*?)(\s*=\s*)([^;]*)`)
	// jsonPair matches a "name": "value" member of JSON embedded in a value.
	jsonPair = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	// inlineFlag matches a --name=value or --name value option inside a
	// value such as an environment variable holding extra arguments.
	inlineFlag = regexp.MustCompile(`(^|\s)(--?[A-Za-z][A-Za-z0-9_-]*)(=|\s+)("[^"]*"|'[^']*'|\S+)`)
	// inlineAssignment matches a NAME=value word inside a value, such as
	// the env prefix of a command line.
	inlineAssignment = regexp.MustCompile(`(^|\s)([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S+)`)
	// winOption matches a Windows-style /name:value or /name=value option.
	winOption = regexp.MustCompile(`^/([A-Za-z][A-Za-z0-9_-]*)([:=])(.*)$`)
)

// Name rules. A name (environment variable, flag, header, query or JSON
// key) is split into words at separators, at lower to upper case changes
// (dbPass) and at the end of an acronym (DBPass). It suggests a secret
// when:
//
//   - it contains one of sensitiveSubstrings anywhere (APIKEY, a TOKEN in
//     GITHUB_TOKEN or authToken), words that rarely occur otherwise;
//   - one of its words is in sensitiveWords (DB_PASS, X-Amz-Signature,
//     --session, API_KEY), so PASSTHROUGH, KEYBOARD or SIGNAL do not;
//   - one of its words ends with one of sensitiveSuffixes (REDISPASS,
//     requirepass, SSHKEY, BASICAUTH) and is not a common word in
//     harmlessWords (MONKEY, COMPASS, BYPASS).
//
// Values under other names are still redacted when they look like tokens.
var (
	sensitiveSubstrings = []string{"PASSWORD", "PASSPHRASE", "SECRET", "TOKEN", "CREDENTIAL", "APIKEY", "COOKIE"}
	sensitiveWords      = map[string]bool{
		"KEY": true, "KEYS": true, "AUTH": true, "AUTHORIZATION": true, "PRIVATE": true,
		"PASS": true, "PASSWD": true, "PWD": true, "SIG": true, "SIGNATURE": true,
		"SESSION": true, "BEARER": true, "CREDS": true,
	}
	sensitiveSuffixes = []string{"KEY", "PASS", "PASSWD", "PWD", "AUTH"}
	harmlessWords     = map[string]bool{
		"MONKEY": true, "DONKEY": true, "TURKEY": true, "HOCKEY": true, "JOCKEY": true,
		"WHISKEY": true, "LACKEY": true, "HOTKEY": true, "TURNKEY": true,
		"BYPASS": true, "COMPASS": true, "ENCOMPASS": true, "OVERPASS": true,
		"UNDERPASS": true, "SURPASS": true, "TRESPASS": true, "OAUTH": true,
	}
)

// sensitiveName reports whether a name suggests that its value is a
// secret, by the rules above.
func sensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range sensitiveSubstrings {
		if strings.Contains(upper, s) {
			return true
		}
	}
	for _, w := range nameWords(name) {
		w = strings.ToUpper(w)
		if sensitiveWords[w] {
			return true
		}
		if harmlessWords[w] {
			continue
		}
		for _, suffix := range sensitiveSuffixes {
			if strings.HasSuffix(w, suffix) {
				return true
			}
		}
	}
	return false
}

// nameWords splits a name at non-alphanumeric separators, at a lower to
// upper case change and before the last capital of an acronym followed by
// a lower-case letter: "DB_PASS" -> DB, PASS; "dbPass" -> db, Pass;
// "DBPass" -> DB, Pass.
func nameWords(name string) []string {
	var words []string
	start := -1
	runes := []rune(name)
	for i, r := range runes {
		alnum := unicode.IsLetter(r) || unicode.IsDigit(r)
		switch {
		case !alnum:
			if start >= 0 {
				words = append(words, string(runes[start:i]))
				start = -1
			}
		case start < 0:
			start = i
		case unicode.IsUpper(r) && unicode.IsLower(runes[i-1]),
			unicode.IsUpper(r) && unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1]):
			words = append(words, string(runes[start:i]))
			start = i
		}
	}
	if start >= 0 {
		words = append(words, string(runes[start:]))
	}
	return words
}

// redactURL keeps a URL's scheme, host and path and replaces the value of
// every query and fragment parameter, and a bare query or fragment, with
// the placeholder: any of them can carry a credential (?sig=..., an access
// token in the fragment). Credentials in the userinfo are removed too.
func redactURL(u string) string {
	u = types.SanitizeURLUserinfo(u, redactedPlaceholder+"@")
	return urlPattern.ReplaceAllStringFunc(u, redactURLParts)
}

func redactURLParts(u string) string {
	base, fragment, hasFragment := strings.Cut(u, "#")
	base, query, hasQuery := strings.Cut(base, "?")
	if scheme, rest, ok := strings.Cut(base, "://"); ok {
		if authority, path, hasPath := strings.Cut(rest, "/"); hasPath {
			base = scheme + "://" + authority + "/" + redactPath(path)
		}
	}
	if hasQuery {
		base += "?" + redactParams(query)
	}
	if hasFragment {
		base += "#" + redactParams(fragment)
	}
	return base
}

// redactParams replaces every value of a query or fragment, and the whole
// text when it is not name=value pairs.
func redactParams(s string) string {
	var b strings.Builder
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '&' && s[i] != ';' {
			continue
		}
		b.WriteString(redactParam(s[start:i]))
		if i < len(s) {
			b.WriteByte(s[i])
		}
		start = i + 1
	}
	return b.String()
}

func redactParam(p string) string {
	name, value, ok := strings.Cut(p, "=")
	switch {
	case p == "":
		return p
	case !ok:
		return redactedPlaceholder
	case value == "":
		return p
	}
	return name + "=" + redactedPlaceholder
}

// redactValue removes secret-shaped parts of a value and keeps the rest:
// URL userinfo, query and fragment values, sensitive query parameters,
// Password= and similar segments of connection strings, sensitive members
// of embedded JSON, sensitive options inside the value, the credential
// after an authorization scheme, and known token formats.
func redactValue(v string) string {
	if v == "" || v == redactedPlaceholder {
		return v
	}
	if red, ok := redactJSONArray(v); ok {
		return red
	}
	v = redactURL(v)
	if strings.ContainsAny(v, "?&") {
		v = queryParam.ReplaceAllStringFunc(v, func(m string) string {
			p := queryParam.FindStringSubmatch(m)
			if p[3] == "" || p[3] == redactedPlaceholder || !sensitiveName(p[2]) {
				return m
			}
			return p[1] + p[2] + "=" + redactedPlaceholder
		})
	}
	if strings.Contains(v, ";") && strings.Contains(v, "=") {
		v = connSegment.ReplaceAllStringFunc(v, func(m string) string {
			p := connSegment.FindStringSubmatch(m)
			if p[5] == "" || !sensitiveName(p[3]) {
				return m
			}
			return p[1] + p[2] + p[3] + p[4] + redactedPlaceholder
		})
	}
	if strings.Contains(v, `"`) {
		v = jsonPair.ReplaceAllStringFunc(v, func(m string) string {
			p := jsonPair.FindStringSubmatch(m)
			if p[3] == "" || !sensitiveName(p[1]) {
				return m
			}
			return `"` + p[1] + `"` + p[2] + `"` + redactedPlaceholder + `"`
		})
	}
	if strings.Contains(v, "-") {
		v = inlineFlag.ReplaceAllStringFunc(v, func(m string) string {
			p := inlineFlag.FindStringSubmatch(m)
			if strings.HasPrefix(p[4], "--") || p[4] == redactedPlaceholder || !sensitiveName(strings.TrimLeft(p[2], "-")) {
				return m
			}
			return p[1] + p[2] + p[3] + redactedPlaceholder
		})
	}
	if strings.Contains(v, "=") {
		v = inlineAssignment.ReplaceAllStringFunc(v, func(m string) string {
			p := inlineAssignment.FindStringSubmatch(m)
			if p[3] == redactedPlaceholder || !sensitiveName(p[2]) {
				return m
			}
			return p[1] + p[2] + "=" + redactedPlaceholder
		})
	}
	v = authScheme.ReplaceAllString(v, "${1}${2}"+redactedPlaceholder)
	return secretShapes.ReplaceAllString(v, redactedPlaceholder)
}

// redactJSONArray redacts a value that is a JSON array of strings, such as
// extra arguments kept in an environment variable, as a list of arguments.
// It reports false for anything else, which redactValue then handles.
func redactJSONArray(v string) (string, bool) {
	trimmed := strings.TrimSpace(v)
	if !strings.HasPrefix(trimmed, "[") {
		return "", false
	}
	var items []json.RawMessage
	if json.Unmarshal([]byte(trimmed), &items) != nil || len(items) == 0 {
		return "", false
	}
	strs := make([]string, len(items))
	for i, it := range items {
		if json.Unmarshal(it, &strs[i]) != nil {
			return "", false
		}
	}
	red := redactArgs(strs)
	if slices.Equal(red, strs) {
		return v, true
	}
	out, err := json.Marshal(red)
	if err != nil {
		return redactedPlaceholder, true
	}
	return string(out), true
}

// redactArgValue redacts one argument, or the value of a --flag=value
// argument: a sensitive "Name: value" header, a sensitive NAME=value
// assignment, a Windows-style /name:value option whose name is sensitive
// or is /p (a password in many Windows tools; /p:Name=Value is read as an
// assignment), and anything redactValue removes.
func redactArgValue(a string) string {
	if m := headerArg.FindStringSubmatch(a); m != nil && !strings.HasPrefix(m[2], "//") && sensitiveName(m[1]) {
		return m[1] + ": " + redactedPlaceholder
	}
	if m := assignment.FindStringSubmatch(a); m != nil && m[2] != "" && sensitiveName(m[1]) {
		return m[1] + "=" + redactedPlaceholder
	}
	if m := winOption.FindStringSubmatch(a); m != nil && m[3] != "" {
		switch {
		case strings.EqualFold(m[1], "p") && strings.Contains(m[3], "="):
			return "/" + m[1] + m[2] + redactArgValue(m[3])
		case strings.EqualFold(m[1], "p") || sensitiveName(m[1]):
			return "/" + m[1] + m[2] + redactedPlaceholder
		}
	}
	return redactValue(a)
}

// redactCommand redacts a server command. A command given as one string
// with arguments (env VAR=value program, docker run -e ...) is split like
// a shell would, for redaction only, and its words are redacted as
// arguments; the original text is kept when nothing in it is secret.
func redactCommand(cmd string) string {
	if !strings.ContainsAny(cmd, " \t") {
		return redactValue(cmd)
	}
	words, ok := shellSplit(cmd)
	if !ok {
		return redactValue(cmd)
	}
	red := redactArgs(words)
	if slices.Equal(red, words) {
		return redactValue(cmd)
	}
	for i, w := range red {
		if w == "" || strings.ContainsAny(w, " \t\"'\\") {
			red[i] = strconv.Quote(w)
		}
	}
	return strings.Join(red, " ")
}

// shellSplit splits s into words at unquoted blanks, honoring single
// quotes, double quotes and backslash escapes. It reports false for an
// unterminated quote.
func shellSplit(s string) ([]string, bool) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped, inWord = true, true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 || escaped {
		return nil, false
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, true
}

// headerFlags take an HTTP header as their value (mcp-remote, curl).
var headerFlags = map[string]bool{"--header": true, "--headers": true, "-H": true, "-header": true}

// redactHeaderArg redacts a "Name: value" header given to a header flag:
// the value is masked unless the header is one whose value is never a
// secret. Anything else is redacted like any argument.
func redactHeaderArg(a string) string {
	if m := headerArg.FindStringSubmatch(a); m != nil && !strings.HasPrefix(m[2], "//") {
		return m[1] + ": " + redactHeader(m[1], m[2])
	}
	return redactArgValue(a)
}

// redactArgs redacts a server's command-line arguments. The value of a
// flag whose name suggests a secret is replaced, whether it follows the
// flag (--api-key x, also a value starting with a single dash) or is
// joined to it (--token=x); a header given to --header or -H keeps only
// its name unless its value is never a secret; a --flag=value whose value
// is a sensitive NAME=value assignment (--env=API_KEY=...) and a separate
// NAME=value argument (-e DB_PASS=...) are redacted too, as are
// secret-shaped values anywhere. Commands, package names and other
// arguments stay visible.
func redactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	valueIsSecret, valueIsHeader := false, false
	for i, a := range args {
		secret, header := valueIsSecret, valueIsHeader
		valueIsSecret, valueIsHeader = false, false
		switch {
		case secret && !strings.HasPrefix(a, "--"):
			out[i] = redactedPlaceholder
			continue
		case header && !strings.HasPrefix(a, "--"):
			out[i] = redactHeaderArg(a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			out[i] = redactArgValue(a)
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		flag := strings.TrimLeft(name, "-")
		switch {
		case hasValue && headerFlags[name]:
			out[i] = name + "=" + redactHeaderArg(value)
		case hasValue && sensitiveName(flag):
			out[i] = name + "=" + redactedPlaceholder
		case hasValue:
			out[i] = name + "=" + redactArgValue(value)
		case headerFlags[a]:
			valueIsHeader = true
			out[i] = a
		default:
			// A one-letter flag cannot be known to be secret; its value is
			// still redacted when it looks like a token.
			valueIsSecret = len(flag) > 1 && sensitiveName(flag)
			out[i] = redactValue(a)
		}
	}
	return out
}

// redactHeaders keeps every header name and masks every value, except the
// values of headers that are never secrets (Accept, Content-Type,
// User-Agent, MCP-Protocol-Version), which are redacted like any value.
func redactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = redactHeader(k, v)
	}
	return out
}
