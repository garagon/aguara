package discover

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

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

// versionPart is a mixed letter-digit part that reads as a version or
// product name, such as v2, x86, h264 or py311.
var versionPart = regexp.MustCompile(`^[A-Za-z]{1,5}[0-9]{1,4}$`)

// readableSegment reports whether seg is two or more parts separated by
// "-", "_", "." or "~", each a word or a number of at most 12 characters,
// or a version-like part such as v2 or x86. Interleaved letter-digit
// groups such as a1b2 are not readable.
func readableSegment(seg string) bool {
	parts := strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '~' })
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		letters := strings.ContainsFunc(p, unicode.IsLetter)
		digits := strings.ContainsFunc(p, unicode.IsDigit)
		if len(p) > 12 || (letters && digits && !versionPart.MatchString(p)) || strings.ContainsAny(p, "=+") {
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
	// queryParam matches one name=value pair of a query outside a URL; the
	// value ends at a blank, a quote or a shell operator.
	queryParam = regexp.MustCompile("([?&])([^=&#\\s]+)=([^&#\\s;|()<>`\"']*)")
	// urlPattern matches a URL with a scheme inside text, up to a blank, a
	// quote, a shell operator or "&&"; a single "&" stays a query
	// separator.
	urlPattern = regexp.MustCompile("[A-Za-z][A-Za-z0-9+.-]*://(?:[^\\s\"'<>;|()`&]|&[^\\s\"'<>;|()`&])+")
	// wholeURL is a value that is one URL: a scheme and no blanks.
	wholeURL = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://\S+$`)
	// headerArg matches a "Name: value" header such as the --header value
	// of an MCP proxy.
	headerArg = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$`)
	// assignment matches a NAME=value argument such as the one after
	// docker's -e.
	assignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$`)
	// connSegment matches one Name=value segment of a semicolon-separated
	// connection string.
	connSegment = regexp.MustCompile(`(^|;)(\s*)([A-Za-z][A-Za-z0-9 _.-]*?)(\s*=\s*)([^;]*)`)
	// connPart is the start of a Name=value segment of a connection string.
	connPart = regexp.MustCompile(`^\s*[A-Za-z][A-Za-z0-9 _.-]*\s*=`)
	// jsonPair matches a "name": "value" member of JSON embedded in a value.
	jsonPair = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	// inlineFlag matches a --name=value or --name value option inside a
	// value such as an environment variable holding extra arguments. An
	// unquoted value ends at a blank or a shell operator and never starts
	// with "--", so a flag without a value does not hide the next flag.
	inlineFlag = regexp.MustCompile(`(^|[\s;&|()<>])(--?[A-Za-z][A-Za-z0-9_-]*)(=|\s+)("[^"]*"|'[^']*'|-?[^\s;&|<>()-][^\s;&|<>()]*)`)
	// inlineAssignment matches a NAME=value word inside a value, such as
	// the env prefix of a command line or PowerShell's $env:NAME=value. An
	// unquoted value ends at a blank or a shell operator.
	inlineAssignment = regexp.MustCompile(`(^|[\s;&|()<>])((?i:\$env:)?[A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|<>()]+)`)
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
// secret, by the rules above. Words are taken both from the name as
// written and from its upper-cased form split only at separators, so odd
// letter case (--ApI-KeY) cannot hide a sensitive word. Flags and query
// parameters use this rule; environment-style names use sensitiveEnvName.
func sensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range sensitiveSubstrings {
		if strings.Contains(upper, s) {
			return true
		}
	}
	words := nameWords(name)
	words = append(words, strings.FieldsFunc(upper, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })...)
	for _, w := range words {
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

// legacyEnvKeys are the substrings that masked an environment value in
// v0.29.0, in any letter case.
var legacyEnvKeys = []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH", "PRIVATE"}

// sensitiveEnvName is the rule for environment-style names: environment
// variables, embedded JSON keys and NAME=value assignments. It never shows
// a value v0.29.0 masked, so a name that merely contains KEY or AUTH
// (KEYSTORE, AUTHDATA, and also KEYBOARD_LAYOUT) is masked as before, in
// addition to everything sensitiveName matches.
func sensitiveEnvName(name string) bool {
	if sensitiveName(name) {
		return true
	}
	upper := strings.ToUpper(name)
	for _, s := range legacyEnvKeys {
		if strings.Contains(upper, s) {
			return true
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
	if wholeURL.MatchString(u) {
		return redactURLParts(u)
	}
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
	return redactText(v, true)
}

// redactText is redactValue; with urls false it leaves URLs alone, for a
// command line whose words, URLs included, were redacted one by one.
func redactText(v string, urls bool) string {
	if v == "" || v == redactedPlaceholder {
		return v
	}
	if red, ok := redactJSON(v); ok {
		return red
	}
	if urls {
		v = redactURL(v)
	}
	if strings.ContainsAny(v, "?&") {
		v = queryParam.ReplaceAllStringFunc(v, func(m string) string {
			p := queryParam.FindStringSubmatch(m)
			if p[3] == "" || p[3] == redactedPlaceholder || !sensitiveName(p[2]) {
				return m
			}
			return p[1] + p[2] + "=" + redactedPlaceholder
		})
	}
	if connectionString(v) {
		v = connSegment.ReplaceAllStringFunc(v, func(m string) string {
			p := connSegment.FindStringSubmatch(m)
			if p[5] == "" || strings.HasPrefix(strings.TrimSpace(p[5]), redactedPlaceholder) || !sensitiveEnvName(p[3]) {
				return m
			}
			return p[1] + p[2] + p[3] + p[4] + redactedPlaceholder
		})
	}
	if strings.Contains(v, `"`) {
		v = jsonPair.ReplaceAllStringFunc(v, func(m string) string {
			p := jsonPair.FindStringSubmatch(m)
			if p[3] == "" || !sensitiveEnvName(p[1]) {
				return m
			}
			return `"` + p[1] + `"` + p[2] + `"` + redactedPlaceholder + `"`
		})
	}
	if strings.Contains(v, "-") {
		v = inlineFlag.ReplaceAllStringFunc(v, func(m string) string {
			p := inlineFlag.FindStringSubmatch(m)
			if strings.HasPrefix(p[4], "--") || unquoted(p[4]) == redactedPlaceholder || !sensitiveName(strings.TrimLeft(p[2], "-")) {
				return m
			}
			return p[1] + p[2] + p[3] + redactedPlaceholder
		})
	}
	if strings.Contains(v, "=") {
		v = inlineAssignment.ReplaceAllStringFunc(v, func(m string) string {
			p := inlineAssignment.FindStringSubmatch(m)
			if unquoted(p[3]) == redactedPlaceholder || !sensitiveEnvName(p[2]) {
				return m
			}
			return p[1] + p[2] + "=" + redactedPlaceholder
		})
	}
	v = authScheme.ReplaceAllString(v, "${1}${2}"+redactedPlaceholder)
	return secretShapes.ReplaceAllString(v, redactedPlaceholder)
}

// connectionString reports whether v reads as a semicolon-separated
// connection string: it has a ";" and every non-empty part is Name=value.
// A shell line such as TOKEN=x;curl host does not.
func connectionString(v string) bool {
	if !strings.Contains(v, ";") {
		return false
	}
	n := 0
	for _, part := range strings.Split(v, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		if !connPart.MatchString(part) {
			return false
		}
		n++
	}
	return n > 0
}

// maxJSONDepth bounds the nesting redactJSON walks; a deeper value is
// masked whole.
const maxJSONDepth = 32

// redactJSON redacts a value that parses as one JSON object or array, such
// as arguments or settings kept in an environment variable, or an entry
// read as JSON text. Every list of strings is redacted as arguments, every
// value under a key with an environment-style sensitive name is masked all
// the way down, and other strings are redacted as values. A value nested
// deeper than maxJSONDepth is masked whole. Unchanged JSON keeps its
// original text; changed JSON is re-encoded without HTML escaping. It
// reports false for anything that is not a JSON object or array.
func redactJSON(v string) (string, bool) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) != nil {
		return "", false
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", false
	}
	red, ok := redactJSONNode(doc, 0)
	if !ok {
		return redactedPlaceholder, true
	}
	if reflect.DeepEqual(red, doc) {
		return v, true
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(red) != nil {
		return redactedPlaceholder, true
	}
	return strings.TrimSuffix(b.String(), "\n"), true
}

func redactJSONNode(n any, depth int) (any, bool) {
	if depth > maxJSONDepth {
		return nil, false
	}
	switch t := n.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			var r any
			var ok bool
			if sensitiveEnvName(k) {
				r, ok = maskJSONNode(v, depth+1)
			} else {
				r, ok = redactJSONNode(v, depth+1)
			}
			if !ok {
				return nil, false
			}
			out[k] = r
		}
		return out, true
	case []any:
		// The strings of a list are redacted as one argument list, in
		// order, whatever else the list holds, so --api-key and its value
		// stay together in ["--api-key", "...", 0].
		out := make([]any, len(t))
		var at []int
		var strs []string
		for i, v := range t {
			if s, isString := v.(string); isString {
				at, strs = append(at, i), append(strs, s)
				continue
			}
			r, ok := redactJSONNode(v, depth+1)
			if !ok {
				return nil, false
			}
			out[i] = r
		}
		for k, s := range redactArgs(strs) {
			out[at[k]] = s
		}
		return out, true
	case string:
		return redactValue(t), true
	}
	return n, true // numbers, booleans, null
}

// maskJSONNode masks every string and number under a sensitive key,
// keeping the shape of objects and arrays.
func maskJSONNode(n any, depth int) (any, bool) {
	if depth > maxJSONDepth {
		return nil, false
	}
	switch t := n.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			r, ok := maskJSONNode(v, depth+1)
			if !ok {
				return nil, false
			}
			out[k] = r
		}
		return out, true
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			r, ok := maskJSONNode(v, depth+1)
			if !ok {
				return nil, false
			}
			out[i] = r
		}
		return out, true
	case string, json.Number:
		return redactedPlaceholder, true
	}
	return n, true // booleans and null carry no secret
}

// redactArgValue redacts one argument, or the value of a --flag=value
// argument: a sensitive "Name: value" header, a sensitive NAME=value
// assignment, a Windows-style /name:value option whose name is sensitive
// or is /p (a password in many Windows tools; /p:Name=Value is read as an
// assignment), and anything redactValue removes.
func redactArgValue(a string) string {
	if m := headerArg.FindStringSubmatch(a); m != nil && m[2] != "" && !strings.HasPrefix(m[2], "//") && sensitiveName(m[1]) {
		return m[1] + ": " + redactedPlaceholder
	}
	if m := assignment.FindStringSubmatch(a); m != nil && m[2] != "" && sensitiveEnvName(m[1]) {
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
// with arguments (env VAR=value program, docker run -e ..., a -c script)
// is split like a shell would, for redaction only. Unquoted blanks and the
// shell operators ; & | < > ( ) end a word, and each command between
// operators is redacted as an argument list, so a flag before an operator
// never takes the next command as its value. Only the bytes of a word that
// change are rewritten, in place, so quoting, operators and all other text
// are kept as written. An unterminated quote (or a trailing backslash)
// masks everything from it to the end.
func redactCommand(cmd string) string {
	if red, ok := redactJSON(cmd); ok {
		return red
	}
	if !strings.ContainsAny(cmd, " \t\n"+shellOperatorChars) {
		return redactValue(cmd)
	}
	words, open := shellWords(cmd)
	values := make([]string, 0, len(words)+1)
	boundary := make([]bool, 0, len(words)+1)
	for _, w := range words {
		values = append(values, w.value)
		boundary = append(boundary, w.afterOp)
	}
	if open != nil {
		// The open word is what precedes the quote, then the masked rest,
		// so the rules for its context (the value after --api-key, a
		// NAME= prefix) still apply to it.
		values = append(values, open.value+redactedPlaceholder)
		boundary = append(boundary, open.afterOp)
	}
	red := make([]string, len(values))
	for lo := 0; lo < len(values); {
		hi := lo + 1
		for hi < len(values) && !boundary[hi] {
			hi++
		}
		copy(red[lo:hi], redactArgs(values[lo:hi]))
		lo = hi
	}
	var b strings.Builder
	last := 0
	for i, w := range words {
		b.WriteString(cmd[last:w.start])
		b.WriteString(rewriteWord(cmd, w, red[i]))
		last = w.end
	}
	if open != nil {
		b.WriteString(cmd[last:open.start])
		if i := len(words); red[i] == values[i] {
			b.WriteString(cmd[open.start:open.end])
		}
		b.WriteString(redactedPlaceholder)
		return redactText(b.String(), false)
	}
	b.WriteString(cmd[last:])
	return redactText(b.String(), false)
}

// shellOperatorChars end a word outside quotes, like a blank: the shell
// reads them as command separators, pipes, redirections and subshells.
const shellOperatorChars = ";&|<>()"

// unquotedSpecials cannot be written unquoted in a word without changing
// how a shell splits it.
const unquotedSpecials = " \t\n'\"\\$`" + shellOperatorChars

// quoteRegion is a quoted string or a backslash escape inside a word, as a
// byte span of the command line that includes the quotes or the backslash.
type quoteRegion struct {
	start, end int
	quote      byte // '\'', '"' or '\\'
}

// shellWord is one word of a command line: its byte span in the original
// text, its value after quote removal, the offset in the text of each
// byte of the value, its quoted and escaped spans, and whether a shell
// operator or a newline separates it from the previous word.
type shellWord struct {
	start, end int
	value      string
	raw        []int
	regions    []quoteRegion
	afterOp    bool
}

// shellWords splits s into words at unquoted blanks and shell operators,
// honoring single quotes, double quotes and backslash escapes. When a
// quote is not closed, or the text ends with a backslash outside quotes,
// it also returns the open word: its start, the offset of that quote or
// backslash as end, and its value up to there; otherwise open is nil.
func shellWords(s string) (words []shellWord, open *shellWord) {
	var cur []byte
	var raw []int
	var regions []quoteRegion
	start, openAt, quoteStart := -1, -1, -1
	var quote byte
	afterOp := false
	prefix := ""
	begin := func(i int) {
		if start < 0 {
			start = i
		}
	}
	keep := func(from, to int) {
		cur = append(cur, s[from:to]...)
		for k := from; k < to; k++ {
			raw = append(raw, k)
		}
	}
	flush := func(end int) {
		if start >= 0 {
			words = append(words, shellWord{start: start, end: end, value: string(cur), raw: raw, regions: regions, afterOp: afterOp})
			cur, raw, regions, start, afterOp = nil, nil, nil, -1, false
		}
	}
	for i := 0; i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		c := s[i]
		switch {
		case c == '\\' && quote != '\'':
			begin(i)
			if i+1 >= len(s) {
				if quote == 0 {
					openAt, prefix = i, string(cur)
				}
				return words, &shellWord{start: start, end: openAt, value: prefix, afterOp: afterOp}
			}
			_, n := utf8.DecodeRuneInString(s[i+1:])
			keep(i+1, i+1+n)
			regions = append(regions, quoteRegion{start: i, end: i + 1 + n, quote: '\\'})
			i += 1 + n
			continue
		case quote != 0:
			if c == quote {
				regions = append(regions, quoteRegion{start: quoteStart, end: i + 1, quote: quote})
				quote = 0
			} else {
				keep(i, i+size)
			}
		case c == '\'' || c == '"':
			begin(i)
			quote, quoteStart = c, i
			openAt, prefix = i, string(cur)
		case c == ' ' || c == '\t':
			flush(i)
		case c == '\n' || strings.IndexByte(shellOperatorChars, c) >= 0:
			flush(i)
			afterOp = true
		default:
			begin(i)
			keep(i, i+size)
		}
		i += size
	}
	if quote != 0 {
		return words, &shellWord{start: start, end: openAt, value: prefix, afterOp: afterOp}
	}
	flush(len(s))
	return words, nil
}

// rewriteWord renders word w of s with its value replaced by red. Only the
// bytes that changed are rewritten: the new text goes where the old bytes
// were, inside the same quotes or in the same unquoted text, widened to
// any quoted or escaped span the change crosses, so the rest of the word
// keeps its quoting. When the new text cannot be written there as it is,
// the whole word is quoted by quoteLike.
func rewriteWord(s string, w shellWord, red string) string {
	orig := s[w.start:w.end]
	v := w.value
	if red == v {
		return orig
	}
	p := 0
	for p < len(v) && p < len(red) && v[p] == red[p] {
		p++
	}
	q := 0
	for q < len(v)-p && q < len(red)-p && v[len(v)-1-q] == red[len(red)-1-q] {
		q++
	}
	if p == len(v)-q {
		return quoteLike(orig, red)
	}
	lo, hi := w.raw[p], w.raw[len(v)-q-1]+1
	for changed := true; changed; {
		changed = false
		for _, rg := range w.regions {
			inside := rg.quote != '\\' && lo > rg.start && hi < rg.end
			if inside || hi <= rg.start || lo >= rg.end {
				continue
			}
			if rg.start < lo {
				lo, changed = rg.start, true
			}
			if rg.end > hi {
				hi, changed = rg.end, true
			}
		}
	}
	var ctx byte
	escaped := false
	for _, rg := range w.regions {
		switch {
		case rg.quote != '\\' && lo > rg.start && hi < rg.end:
			ctx = rg.quote
		case rg.quote == '\\' && rg.start >= lo && rg.end <= hi:
			escaped = true
		}
	}
	insert := red[p : len(red)-q]
	var fits bool
	switch ctx {
	case '\'':
		fits = !strings.Contains(insert, "'")
	case '"':
		fits = !strings.ContainsAny(insert, "\"\\`") && !(escaped && strings.Contains(insert, "$"))
	default:
		fits = !strings.ContainsAny(strings.ReplaceAll(insert, redactedPlaceholder, ""), unquotedSpecials)
	}
	if !fits {
		return quoteLike(orig, red)
	}
	return s[w.start:lo] + insert + s[hi:w.end]
}

// quoteLike renders a redacted word for the command line when it cannot
// be edited in place. A word that was one quoted string keeps that quote
// when the new value allows it; a word that needs no quoting apart from
// the placeholder stays unquoted; any other word gets single quotes.
func quoteLike(orig, value string) string {
	if n := len(orig); n >= 2 && (orig[0] == '"' || orig[0] == '\'') && orig[n-1] == orig[0] && !strings.ContainsRune(orig[1:n-1], rune(orig[0])) {
		inner := orig[1 : n-1]
		if orig[0] == '"' && !strings.ContainsAny(value, "\"\\`") && (!strings.Contains(value, "$") || !strings.Contains(inner, `\`)) {
			return `"` + value + `"`
		}
		if orig[0] == '\'' && !strings.Contains(value, "'") {
			return "'" + value + "'"
		}
	}
	if value != "" && !strings.ContainsAny(strings.ReplaceAll(value, redactedPlaceholder, ""), unquotedSpecials) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// unquoted strips one pair of surrounding quotes, for comparing a matched
// value with the placeholder.
func unquoted(s string) string {
	if n := len(s); n >= 2 && (s[0] == '"' || s[0] == '\'') && s[n-1] == s[0] {
		return s[1 : n-1]
	}
	return s
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

// scriptFlag is a shell option cluster that takes a command string: -c,
// or -c combined with other one-letter options (-lc, -ec, -euc).
var scriptFlag = regexp.MustCompile(`^-[a-z]{0,3}c[a-z]{0,3}$`)

// takesScript reports whether the argument after a is a command line: -c
// and its clusters for POSIX shells, -Command for PowerShell, and /c or /k
// for cmd.
func takesScript(a string) bool {
	return (len(a) <= 5 && scriptFlag.MatchString(a)) || strings.EqualFold(a, "-command") || strings.EqualFold(a, "/c") || strings.EqualFold(a, "/k")
}

// redactScript redacts a command line given as one argument: one word is
// redacted as an argument, anything with blanks or shell operators as a
// command.
func redactScript(a string) string {
	if !strings.ContainsAny(a, " \t\n"+shellOperatorChars) {
		return redactArgValue(a)
	}
	return redactCommand(a)
}

// redactArgs redacts a server's command-line arguments. The value of a
// flag whose name suggests a secret is replaced, whether it follows the
// flag (--api-key x, also a value starting with a single dash) or is
// joined to it (--token=x); a header given to --header or -H keeps only
// its name unless its value is never a secret; a --flag=value whose value
// is a sensitive NAME=value assignment (--env=API_KEY=...) and a separate
// NAME=value argument (-e DB_PASS=...) are redacted too, as are
// secret-shaped values anywhere. The argument after -c (and -lc, /c, /k,
// -Command) is a command line and is redacted as one. Commands, package
// names and other arguments stay visible.
func redactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	valueIsSecret, valueIsHeader, valueIsScript := false, false, false
	for i, a := range args {
		secret, header, script := valueIsSecret, valueIsHeader, valueIsScript
		valueIsSecret, valueIsHeader, valueIsScript = false, false, false
		switch {
		case secret && !strings.HasPrefix(a, "--"):
			out[i] = redactedPlaceholder
			continue
		case header && !strings.HasPrefix(a, "--"):
			out[i] = redactHeaderArg(a)
			continue
		case script && (!strings.HasPrefix(a, "-") || strings.ContainsAny(a, " \t\n"+shellOperatorChars)):
			out[i] = redactScript(a)
			continue
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			out[i] = redactArgValue(a)
			valueIsScript = takesScript(a)
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
			valueIsScript = !valueIsSecret && takesScript(a)
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
