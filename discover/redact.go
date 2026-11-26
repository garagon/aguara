package discover

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strconv"
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
// product name, such as v2, x86, h264, py311, es2015 or webpack5.
var versionPart = regexp.MustCompile(`^[A-Za-z]{1,8}[0-9]{1,4}$`)

// readableSegment reports whether seg is two or more parts separated by
// "-", "_", "." or "~", each a word or a number of at most 12 characters,
// or a version-like part such as v2 or x86, with at least one word of
// three or more letters. Interleaved letter-digit groups such as a1b2, and
// segments made only of groups such as ab12, are not readable.
func readableSegment(seg string) bool {
	parts := strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '~' })
	if len(parts) < 2 {
		return false
	}
	word := false
	for _, p := range parts {
		letters := strings.ContainsFunc(p, unicode.IsLetter)
		digits := strings.ContainsFunc(p, unicode.IsDigit)
		if len(p) > 12 || (letters && digits && !versionPart.MatchString(p)) || strings.ContainsAny(p, "=+") {
			return false
		}
		if len(p) >= 3 && !strings.ContainsFunc(p, func(r rune) bool { return !unicode.IsLetter(r) }) {
			word = true
		}
	}
	return word
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
	// textURL matches a URL with a scheme inside text, up to a blank or a
	// quote.
	textURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	// textUserinfo finds a user:password@ part after a scheme even when the
	// password holds characters a URL cannot, such as a blank or a quote.
	textUserinfo = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s@]*:[^/@]*@`)
	// textAuthScheme finds the word after an authorization scheme or the
	// word token (fish's set -x TOKEN value too); plainHit decides whether
	// that word is a credential.
	textAuthScheme = regexp.MustCompile(`(?i)\b(?:bearer|basic|token)\s+(\S+)`)
	// optionWord is a long option, such as the --hostname of gh auth token
	// --hostname: not a credential after a scheme word. A credential that
	// starts with "--" (base64url can) does not read as one.
	optionWord = regexp.MustCompile(`^--[a-z][a-z0-9-]*(?:=|$)`)
	// fishSet is fish's set [flags] NAME value.
	fishSet = regexp.MustCompile(`(?:^|[\s;&|()])set\s+(?:-[A-Za-z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)\s+(\S)`)
	// wholeURL is a value that is one URL: a scheme and no blanks.
	wholeURL = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://\S+$`)
	// headerArg matches a "Name: value" header such as the --header value
	// of an MCP proxy.
	headerArg = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$`)
	// assignment matches a NAME=value argument such as the one after
	// docker's -e.
	assignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$`)
	// psEnv matches PowerShell's $env:NAME, $env:NAME= and
	// $env:NAME = value (the name, the "=" with its blanks, the value).
	psEnv = regexp.MustCompile(`^(\$(?i:env):([A-Za-z_][A-Za-z0-9_]*))(\s*=\s*)?(.*)$`)
	// connSegment matches one Name=value segment of a semicolon-separated
	// connection string.
	connSegment = regexp.MustCompile(`(^|;)(\s*)([A-Za-z][A-Za-z0-9 _.-]*?)(\s*=\s*)([^;]*)`)
	// connPart is the start of a Name=value segment of a connection string.
	connPart = regexp.MustCompile(`^\s*[A-Za-z][A-Za-z0-9 _.-]*\s*=`)
	// jsonPair matches a "name": "value" member of JSON in text.
	jsonPair = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	// winOption matches a Windows-style /name:value or /name=value option.
	winOption = regexp.MustCompile(`^/([A-Za-z][A-Za-z0-9_-]*)([:=])(.*)$`)
	// flagToken is a flag name: one or two dashes and a name.
	flagToken = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9_.-]*$`)
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
	return textURL.ReplaceAllStringFunc(u, redactURLParts)
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

// redactValue redacts a value that is not a command line: an environment
// value under a name that is not sensitive, a shown header value, the URL
// of a remote server, a string inside JSON, or an argument read as one
// value. A value with a grammar is redacted by its parts: one URL (its
// userinfo, query, fragment and credential-like path segments), JSON
// (redactJSON), or a connection string whose every ";" part is Name=value
// (its sensitive parts). Any other value is all or nothing: when any rule
// matches anywhere in it (plainHit), the whole value is replaced, so no
// part of a secret that holds an operator, an escape or a quote is shown.
func redactValue(v string) string {
	if v == "" || v == redactedPlaceholder {
		return v
	}
	if red, ok := redactJSON(v); ok {
		return red
	}
	if wholeURL.MatchString(v) {
		if textUserinfo.MatchString(v) && types.SanitizeURLUserinfo(v, redactedPlaceholder+"@") == v {
			// A password the URL reader cannot delimit.
			return redactedPlaceholder
		}
		return secretShapes.ReplaceAllString(redactURL(v), redactedPlaceholder)
	}
	if connectionString(v) {
		return redactConnectionString(v)
	}
	if plainHit(v) {
		return redactedPlaceholder
	}
	return v
}

// redactConnectionString masks the value of each part whose name is
// sensitive or whose value has a hit of its own.
func redactConnectionString(v string) string {
	return connSegment.ReplaceAllStringFunc(v, func(m string) string {
		p := connSegment.FindStringSubmatch(m)
		if p[5] == "" || !sensitiveEnvName(p[3]) && !plainHit(p[5]) {
			return m
		}
		return p[1] + p[2] + p[3] + p[4] + redactedPlaceholder
	})
}

// plainHit reports whether any redaction rule matches anywhere in v: a
// known token format, a credential after an authorization scheme, a URL
// with userinfo, a query, a fragment or a credential-like path segment, a
// sensitive name with a value (sensitivePairIn), fish's set NAME value
// with a sensitive name, or a sensitive member of JSON text. A match whose
// value is already the placeholder is not a hit. It is the one source of
// hits for plain mode and for the backstop of command mode.
func plainHit(v string) bool {
	if secretShapes.MatchString(v) || textUserinfo.MatchString(v) {
		return true
	}
	for _, m := range textAuthScheme.FindAllStringSubmatchIndex(v, -1) {
		// TOKEN = x is a pair (found as one below), and an option is not a
		// credential.
		w := v[m[2]:m[3]]
		if w == "=" || w == ":" || optionWord.MatchString(w) || redactedAt(strings.TrimLeft(v[m[2]:], "=:")) {
			continue
		}
		return true
	}
	if strings.Contains(v, "://") && redactURL(v) != v {
		return true
	}
	if sensitivePairIn(v) {
		return true
	}
	for _, m := range fishSet.FindAllStringSubmatchIndex(v, -1) {
		if sensitiveEnvName(v[m[2]:m[3]]) && !redactedAt(v[m[4]:]) {
			return true
		}
	}
	if strings.Contains(v, `"`) {
		for _, p := range jsonPair.FindAllStringSubmatch(v, -1) {
			if p[3] != "" && p[3] != redactedPlaceholder && sensitiveEnvName(p[1]) {
				return true
			}
		}
	}
	return false
}

// redactedAt reports whether s starts with the placeholder, also after an
// opening quote or an authorization scheme (Bearer [REDACTED]): a value
// that was redacted already.
func redactedAt(s string) bool {
	s = strings.TrimLeft(s, `"'`)
	if i := strings.IndexAny(s, " \t"); i > 0 && isAuthScheme(s[:i]) {
		s = strings.TrimLeft(s[i:], " \t")
	}
	return strings.HasPrefix(s, redactedPlaceholder)
}

// isNameByte reports whether c can be part of a name in text.
func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// sensitivePairIn reports whether v holds a sensitive name followed by a
// value anywhere: NAME=value or NAME = value (also $env:NAME = value and
// ?name=value), Name: value and /name:value, --flag=value or --flag value.
// Names before "=" follow the environment-name rule; flags and names before
// ":" follow the precise rule, so --keyboard us is not a hit.
func sensitivePairIn(v string) bool {
	for i := 0; i < len(v); {
		if !isNameByte(v[i]) {
			i++
			continue
		}
		j := i
		for j < len(v) && isNameByte(v[j]) {
			j++
		}
		name, rest := v[i:j], v[j:]
		i = j
		bare := strings.TrimLeft(name, "-")
		if bare == "" {
			continue
		}
		flag := len(bare) < len(name)
		after := strings.TrimLeft(rest, " \t")
		switch {
		case strings.HasPrefix(after, "=") || strings.HasPrefix(after, ":"):
			value := strings.TrimLeft(after[1:], " \t")
			if value == "" || strings.HasPrefix(value, "//") || after[0] == '=' && value[0] == '=' || redactedAt(value) {
				continue
			}
			if flag || after[0] == ':' {
				if sensitiveName(bare) {
					return true
				}
			} else if sensitiveEnvName(bare) {
				return true
			}
		case flag && len(after) < len(rest) && after != "" && !strings.HasPrefix(after, "--") && !redactedAt(after) && len(bare) > 1 && sensitiveName(bare):
			return true
		}
	}
	return false
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
// argument: a sensitive "Name: value" header, PowerShell's $env:NAME =
// value or a NAME=value assignment with a sensitive name (only the value
// is replaced; the value of another NAME=value is redacted by
// redactValue), a Windows-style /name:value option whose name is sensitive
// or is /p (a password in many Windows tools; /p:Name=Value is read as an
// assignment), and otherwise the whole argument as one value (redactValue).
func redactArgValue(a string) string {
	if m := headerArg.FindStringSubmatch(a); m != nil && m[2] != "" && !strings.HasPrefix(m[2], "//") && sensitiveName(m[1]) {
		return m[1] + ": " + redactedPlaceholder
	}
	if m := psEnv.FindStringSubmatch(a); m != nil && m[3] != "" && m[4] != "" && sensitiveEnvName(m[2]) {
		return m[1] + m[3] + redactedPlaceholder
	}
	if m := assignment.FindStringSubmatch(a); m != nil && m[2] != "" {
		if sensitiveEnvName(m[1]) {
			return m[1] + "=" + redactedPlaceholder
		}
		return m[1] + "=" + redactValue(m[2])
	}
	if m := winOption.FindStringSubmatch(a); m != nil && m[3] != "" {
		switch {
		case strings.EqualFold(m[1], "p") && strings.Contains(m[3], "="):
			return "/" + m[1] + m[2] + redactArgValue(m[3])
		case strings.EqualFold(m[1], "p") || sensitiveName(m[1]):
			return "/" + m[1] + m[2] + redactedPlaceholder
		}
		return "/" + m[1] + m[2] + redactValue(m[3])
	}
	return redactValue(a)
}

// redactCommand redacts a server command. A command given as one string
// with arguments (env VAR=value program, docker run -e ..., a -c script)
// is split like a shell would, for redaction only. Unquoted blanks and the
// shell operators ; & | < > ( ) end a word, and each simple command (the
// words between operators) is redacted as an argument list, so a flag
// before an operator never takes the next command as its value. Only the
// bytes of a word that change are rewritten, in place, so quoting,
// operators and all other text are kept as written. A command
// substitution, $(...) or `...`, stays inside its word, and its body is
// redacted as a command line. The word after <<< to a shell, and the
// arguments of echo or printf piped into a shell, are command lines too;
// a here-string to another program is one plain value. An unterminated
// quote (or a trailing backslash or an unterminated substitution) masks
// everything from it to the end.
//
// Command mode never shows what plain mode would mask: when a simple
// command still has a plain-mode hit (plainHit) after the word rules, it
// is masked from its first argument to its end, and the other simple
// commands of the line stay as they are. The rebuilt line is not read
// again; only a known token format still present in it is masked.
func redactCommand(cmd string) string {
	return redactCommandAt(cmd, 0)
}

// redactCommandAt is redactCommand for a command line nested depth
// command substitutions deep.
func redactCommandAt(cmd string, depth int) string {
	if red, ok := redactJSON(cmd); ok {
		return red
	}
	if !strings.ContainsAny(cmd, shellSyntax) {
		return redactArgValue(cmd)
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
	script := make([]bool, len(values))
	masked := map[int]int{} // first masked word of a simple command -> its end
	prev := -1
	for lo := 0; lo < len(values); {
		hi := lo + 1
		for hi < len(values) && !boundary[hi] {
			hi++
		}
		segRed, segScript := redactArgsAt(values[lo:hi], depth)
		copy(red[lo:hi], segRed)
		copy(script[lo:hi], segScript)
		if lo < len(words) && strings.HasSuffix(words[lo].op, "<<<") {
			if prev >= 0 && isShell(values[prev]) {
				red[lo], script[lo] = redactScript(values[lo], depth), true
			} else {
				// Input of a program that is not a shell: one plain value.
				red[lo], script[lo] = redactValue(values[lo]), false
			}
		}
		if hi < len(words) && pipedIntoShell(values[lo], words[hi]) {
			for k := lo + 1; k < hi; k++ {
				if !strings.HasPrefix(values[k], "-") {
					red[k], script[k] = redactScript(values[k], depth), true
				}
			}
		}
		if text := backstopText(red[lo:hi], script[lo:hi]); plainHit(text) {
			if onBackstop != nil {
				onBackstop(text)
			}
			from := lo + 1
			if from == hi || plainHit(backstopText(red[lo:lo+1], script[lo:lo+1])) {
				from = lo
			}
			masked[from] = hi
		}
		prev, lo = lo, hi
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(words); i++ {
		w := words[i]
		b.WriteString(cmd[last:w.start])
		if end, ok := masked[i]; ok {
			b.WriteString(redactedPlaceholder)
			if end > len(words) {
				// The open word is in the masked command: all the rest.
				return secretShapes.ReplaceAllString(b.String(), redactedPlaceholder)
			}
			last, i = words[end-1].end, end-1
			continue
		}
		b.WriteString(rewriteWord(cmd, w, red[i]))
		last = w.end
	}
	if open != nil {
		b.WriteString(cmd[last:open.start])
		i := len(words)
		if _, cut := masked[i]; !cut && red[i] == values[i] && openPrefix.MatchString(open.value) {
			b.WriteString(cmd[open.start:open.end])
		}
		b.WriteString(redactedPlaceholder)
		return secretShapes.ReplaceAllString(b.String(), redactedPlaceholder)
	}
	b.WriteString(cmd[last:])
	return secretShapes.ReplaceAllString(b.String(), redactedPlaceholder)
}

// openPrefix is the part of a word before an unterminated quote that is
// shown: nothing, or a NAME=, $env:NAME= or --flag= whose value starts at
// the quote. Any other text before the quote may be part of the secret it
// opens (a URL password with a quote in it) and is masked with it.
var openPrefix = regexp.MustCompile(`^(?:(?:\$(?i:env):)?[A-Za-z_][A-Za-z0-9_.-]*=|--?[A-Za-z][A-Za-z0-9_.-]*=)?$`)

// backstopText is the text of a redacted simple command or argument list
// that the backstop reads: the words joined by blanks, without the command
// lines in it (scripts and substitution bodies), which were checked as
// command lines of their own.
func backstopText(words []string, script []bool) string {
	parts := make([]string, 0, len(words))
	for k, w := range words {
		if !script[k] {
			parts = append(parts, stripSubstitutions(w))
		}
	}
	return strings.Join(parts, " ")
}

// stripSubstitutions removes the closed command substitutions from s; from
// the first one that is not closed, the rest of s is kept as it is.
func stripSubstitutions(s string) string {
	if !strings.ContainsAny(s, "$`") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '`' || s[i] == '$' && i+1 < len(s) && s[i+1] == '(' {
			end := substitutionEnd(s, i)
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			i = end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// onBackstop, when set (by tests), is called with the text of each simple
// command or argument list the backstop masks.
var onBackstop func(text string)

// shells are the programs that run a command line given on their input.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "pwsh": true}

// isShell reports whether program is a shell, by its base name.
func isShell(program string) bool {
	return shells[program[strings.LastIndexByte(program, '/')+1:]]
}

// pipedIntoShell reports whether a command starting with program is echo
// or printf and its output goes through a pipe into a shell, the word next.
func pipedIntoShell(program string, next shellWord) bool {
	return (program == "echo" || program == "printf") && next.op == "|" && isShell(next.value)
}

// shellOperatorChars end a word outside quotes, like a blank: the shell
// reads them as command separators, pipes, redirections and subshells.
const shellOperatorChars = ";&|<>()"

// unquotedSpecials cannot be written unquoted in a word without changing
// how a shell splits it.
const unquotedSpecials = " \t\n'\"\\$`" + shellOperatorChars

// quoteRegion is a quoted string, a backslash escape or a command
// substitution inside a word, as a byte span of the command line that
// includes the quotes, the backslash or the $( ) and backticks.
type quoteRegion struct {
	start, end int
	quote      byte // '\'', '"', '\\' or '$'
}

// shellWord is one word of a command line: its byte span in the original
// text, its value after quote removal, the offset in the text of each
// byte of the value, its quoted and escaped spans, whether a shell
// operator or a newline separates it from the previous word, and that
// operator text (blanks left out).
type shellWord struct {
	start, end int
	value      string
	raw        []int
	regions    []quoteRegion
	afterOp    bool
	op         string
}

// shellWords splits s into words at unquoted blanks and shell operators,
// honoring single quotes, double quotes, backslash escapes and command
// substitutions, which are kept verbatim in their word. When a quote or a
// substitution is not closed, or the text ends with a backslash outside
// quotes, it also returns the open word: its start, the offset of that
// quote, substitution or backslash as end, and its value up to there;
// otherwise open is nil.
func shellWords(s string) (words []shellWord, open *shellWord) {
	var cur []byte
	var raw []int
	var regions []quoteRegion
	start, openAt, quoteStart := -1, -1, -1
	var quote byte
	afterOp := false
	prefix := ""
	pendingOp, wordOp := "", ""
	begin := func(i int) {
		if start < 0 {
			start = i
			wordOp, pendingOp = pendingOp, ""
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
			words = append(words, shellWord{start: start, end: end, value: string(cur), raw: raw, regions: regions, afterOp: afterOp, op: wordOp})
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
		case quote != '\'' && (c == '`' || c == '$' && i+1 < len(s) && s[i+1] == '('):
			begin(i)
			end := substitutionEnd(s, i)
			if end < 0 {
				if quote == 0 {
					openAt, prefix = i, string(cur)
				}
				return words, &shellWord{start: start, end: openAt, value: prefix, afterOp: afterOp}
			}
			keep(i, end)
			regions = append(regions, quoteRegion{start: i, end: end, quote: '$'})
			i = end
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
			pendingOp += string(c)
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

// substitutionEnd returns the offset just past the command substitution
// that starts at s[i], "$(" or a backtick, or -1 when it is not closed.
// Quotes, escapes and nested parentheses inside it are skipped.
func substitutionEnd(s string, i int) int {
	if s[i] == '`' {
		for j := i + 1; j < len(s); j++ {
			switch s[j] {
			case '\\':
				j++
			case '`':
				return j + 1
			}
		}
		return -1
	}
	depth := 0
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '\'':
			k := strings.IndexByte(s[j+1:], '\'')
			if k < 0 {
				return -1
			}
			j += k + 1
		case '"':
			for j++; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				return -1
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return -1
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
			if rg.quote == '$' {
				// Verbatim in the value: its bytes map one to one.
				continue
			}
			inside := (rg.quote == '\'' || rg.quote == '"') && lo > rg.start && hi < rg.end
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
	// The value bytes of the widened span, and what replaces them.
	vlo, vhi := p, len(v)-q
	for vlo > 0 && w.raw[vlo-1] >= lo {
		vlo--
	}
	for vhi < len(v) && w.raw[vhi] < hi {
		vhi++
	}
	insert := red[vlo : len(red)-(len(v)-vhi)]
	var ctx byte
	escaped, subst := false, false
	for _, rg := range w.regions {
		switch {
		case (rg.quote == '\'' || rg.quote == '"') && lo > rg.start && hi < rg.end:
			ctx = rg.quote
		case rg.quote == '\\' && rg.start >= lo && rg.end <= hi:
			escaped = true
		case rg.quote == '$' && lo < rg.end && hi > rg.start:
			subst = true
		}
	}
	if subst {
		// Redacted shell text in place of shell text inside a substitution.
		return s[w.start:lo] + insert + s[hi:w.end]
	}
	var fits bool
	switch ctx {
	case '\'':
		fits = !strings.Contains(insert, "'")
	case '"':
		fits = !strings.ContainsAny(insert, "\"\\`") && (!escaped || !strings.Contains(insert, "$"))
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

// redactScript redacts a command line given as one argument: a plain word
// is redacted as an argument, anything with blanks, quotes, escapes,
// substitutions or shell operators as a command.
func redactScript(a string, depth int) string {
	if !strings.ContainsAny(a, shellSyntax) {
		return redactArgValue(a)
	}
	return redactCommandAt(a, depth)
}

// shellSyntax are the characters that make a string more than one plain
// word for a shell.
const shellSyntax = " \t\n'\"\\`$" + shellOperatorChars

// scriptOptions are long options known to take a shell command line.
// Others named like one (--command, --run) are not known to be shell lines
// and their value is one value.
var scriptOptions = map[string]bool{"--exec": true}

// maxSubstitutionDepth bounds how deep command substitutions are read as
// command lines; a deeper one is masked whole.
const maxSubstitutionDepth = 4

// hideSubstitutions replaces each command substitution in a, $(...) or
// `...`, with a marker and returns a function that puts them back, each
// with its body redacted as a command line, so the rules of a word apply
// only to the text outside its substitutions. A marker the rules removed
// takes its substitution with it. A substitution deeper than
// maxSubstitutionDepth is masked whole. When one is not closed nothing is
// hidden and the rules see the whole argument, so the text before it is
// never judged alone (in a command line the shell reader has already
// masked an unterminated substitution to the end).
func hideSubstitutions(a string, depth int) (string, func(string) string) {
	keep := func(s string) string { return s }
	if !strings.ContainsAny(a, "$`") || strings.IndexByte(a, 0) >= 0 {
		return a, keep
	}
	var b strings.Builder
	var spans []string
	for i := 0; i < len(a); {
		c := a[i]
		if c != '`' && (c != '$' || i+1 >= len(a) || a[i+1] != '(') {
			b.WriteByte(c)
			i++
			continue
		}
		end := substitutionEnd(a, i)
		if end < 0 {
			return a, keep
		}
		red := redactedPlaceholder
		if depth < maxSubstitutionDepth {
			open := 2
			if c == '`' {
				open = 1
			}
			red = a[i:i+open] + redactCommandAt(a[i+open:end-1], depth+1) + a[end-1:end]
		}
		b.WriteString(substitutionMarker(len(spans)))
		spans = append(spans, red)
		i = end
	}
	if spans == nil {
		return a, keep
	}
	return b.String(), func(s string) string {
		// One pass: each marker the rules kept is put back once.
		var out strings.Builder
		used := make([]bool, len(spans))
		for {
			i := strings.IndexByte(s, 0)
			if i < 0 {
				break
			}
			j := strings.IndexByte(s[i+1:], 0)
			if j < 0 {
				break
			}
			k, err := strconv.Atoi(s[i+1 : i+1+j])
			out.WriteString(s[:i])
			if err == nil && k >= 0 && k < len(spans) && !used[k] {
				out.WriteString(spans[k])
				used[k] = true
			} else {
				out.WriteString(s[i : i+2+j])
			}
			s = s[i+2+j:]
		}
		out.WriteString(s)
		return out.String()
	}
}

// substitutionMarker stands for the k-th substitution of a word.
func substitutionMarker(k int) string {
	return "\x00" + strconv.Itoa(k) + "\x00"
}

// argNext is what an argument makes of the one after it.
type argNext int

const (
	nextAny        argNext = iota
	nextSecret             // the value of a sensitive flag, name or "Name:"
	nextCredential         // the word after Bearer, Basic or Token: masked unless an option
	nextHeader             // the value of --header or -H
	nextScript             // a command line, after -c, /c, /k, -Command or --exec
	nextEquals             // after a sensitive NAME or $env:NAME: "=" or "=value"
)

// redactArgs redacts a server's command-line arguments, which are words:
// only the secret part of a word is replaced. The value of a flag whose
// name suggests a secret is replaced, whether it follows the flag
// (--api-key x, also a value starting with a single dash) or is joined to
// it (--token=x); a header given to --header or -H keeps only its name
// unless its value is never a secret; a sensitive NAME=value, NAME = value
// or $env:NAME = value keeps its name; the word after a sensitive "Name:"
// and the word after Bearer, Basic or Token is a credential. The argument
// after -c (and -lc, /c, /k, -Command), the value of --exec and the
// arguments of eval are command lines and are redacted as one, as is the
// body of a command substitution in any argument. Any other word is
// redacted as one value (redactArgValue). Commands, package names and
// other arguments stay visible. When the redacted arguments still have a
// plain-mode hit, every argument is masked (the backstop of
// redactCommand).
func redactArgs(args []string) []string {
	out, script := redactArgsAt(args, 0)
	if text := backstopText(out, script); len(out) > 0 && plainHit(text) {
		if onBackstop != nil {
			onBackstop(text)
		}
		for i := range out {
			out[i] = redactedPlaceholder
		}
	}
	return out
}

// redactArgsAt is redactArgs, without the backstop, for arguments nested
// depth command substitutions deep. It also reports which arguments were
// redacted as command lines.
func redactArgsAt(args []string, depth int) ([]string, []bool) {
	if args == nil {
		return nil, nil
	}
	out := make([]string, len(args))
	script := make([]bool, len(args))
	next := nextAny
	evalArgs := false
	for i, a := range args {
		state := next
		next = nextAny
		switch {
		case (state == nextSecret || state == nextCredential) && a == "=":
			// NAME = value: the value is the word after.
			out[i], next = a, nextSecret
			continue
		case (state == nextSecret || state == nextCredential) && isAuthScheme(a):
			// Authorization: Bearer value: the credential is the word after.
			out[i], next = a, nextCredential
			continue
		case (state == nextSecret || state == nextCredential) && strings.HasPrefix(a, "="):
			out[i] = "=" + redactedPlaceholder
			continue
		case state == nextSecret && !strings.HasPrefix(a, "--"),
			state == nextCredential && !optionWord.MatchString(a):
			// After a scheme word only an option (--hostname) is not the
			// credential; a credential can start with "--".
			out[i] = redactedPlaceholder
			continue
		case state == nextHeader && !strings.HasPrefix(a, "--"):
			out[i] = redactHeaderArg(a)
			continue
		case (state == nextScript || evalArgs) && (!strings.HasPrefix(a, "-") || strings.ContainsAny(a, " \t\n"+shellOperatorChars)):
			out[i], script[i] = redactScript(a, depth), true
			continue
		case state == nextEquals && a == "=":
			out[i], next = a, nextSecret
			continue
		case state == nextEquals && strings.HasPrefix(a, "="):
			out[i] = "=" + redactedPlaceholder
			continue
		}
		lit, restore := hideSubstitutions(a, depth)
		var red string
		red, next = redactArg(lit, depth)
		out[i] = restore(red)
		evalArgs = evalArgs || a == "eval"
	}
	return out, script
}

// redactArg redacts one argument that is not the value of the one before
// it and says what it makes of the next one.
func redactArg(a string, depth int) (string, argNext) {
	if a == "--" || !strings.HasPrefix(a, "-") {
		return redactWord(a)
	}
	name, value, hasValue := strings.Cut(a, "=")
	if !flagToken.MatchString(name) {
		// Text that starts with a dash but is not a flag, such as one
		// argument holding several options: one value.
		return redactValue(a), nextAny
	}
	flag := strings.TrimLeft(name, "-")
	switch {
	case hasValue && headerFlags[name]:
		return name + "=" + redactHeaderArg(value), nextAny
	case hasValue && sensitiveName(flag):
		return name + "=" + redactedPlaceholder, nextAny
	case hasValue && scriptOptions[name]:
		return name + "=" + redactScript(value, depth), nextAny
	case hasValue:
		return name + "=" + redactArgValue(value), nextAny
	case headerFlags[a]:
		return a, nextHeader
	case len(flag) > 1 && sensitiveName(flag):
		// A one-letter flag cannot be known to be secret; its value is
		// still redacted when it holds a secret.
		return redactValue(a), nextSecret
	case takesScript(a) || scriptOptions[a]:
		return redactValue(a), nextScript
	}
	return redactValue(a), nextAny
}

// envName is a name that can stand before "=" in a NAME = value pair.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// isAuthScheme reports whether a is Bearer, Basic or Token, in any case.
func isAuthScheme(a string) bool {
	return strings.EqualFold(a, "bearer") || strings.EqualFold(a, "basic") || strings.EqualFold(a, "token")
}

// redactWord redacts an argument that is not a flag and says what it
// makes of the next one: $env:NAME, NAME= and a sensitive "Name:" leave
// their value to the next word, a sensitive NAME alone may be followed by
// "=" and its value, and the word after Bearer, Basic or Token is the
// credential.
func redactWord(a string) (string, argNext) {
	if m := psEnv.FindStringSubmatch(a); m != nil && sensitiveEnvName(m[2]) {
		switch {
		case m[3] != "" && m[4] != "":
			return m[1] + m[3] + redactedPlaceholder, nextAny
		case m[3] != "":
			return a, nextSecret
		case m[4] == "":
			return a, nextEquals
		}
	}
	if m := assignment.FindStringSubmatch(a); m != nil && m[2] == "" && sensitiveEnvName(m[1]) {
		return a, nextSecret
	}
	out := redactArgValue(a)
	switch {
	case takesScript(a):
		return out, nextScript
	case isAuthScheme(a):
		return out, nextCredential
	case strings.HasSuffix(a, ":") && sensitiveName(nameBeforeColon(a)):
		return out, nextSecret
	case envName.MatchString(a) && sensitiveEnvName(a):
		return out, nextEquals
	}
	return out, nextAny
}

// nameBeforeColon is the name that ends at the final ":" of a, such as
// X-Api-Key in X-Api-Key: or token in {token:.
func nameBeforeColon(a string) string {
	a = strings.TrimSuffix(a, ":")
	i := len(a)
	for i > 0 && isNameByte(a[i-1]) {
		i--
	}
	return a[i:]
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
