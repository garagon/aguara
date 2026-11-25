package discover

import (
	"regexp"
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
	`-----BEGIN[ A-Z]*PRIVATE KEY(?: BLOCK)?-----`,
}, "|"))

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
)

// sensitiveWords are names that suggest a secret only as a whole word
// (DB_PASS, --passphrase, X-Amz-Signature, sessionId), so names that merely
// contain the letters, such as PASSTHROUGH, BYPASS or DESIGN, stay visible.
var sensitiveWords = map[string]bool{
	"PASS": true, "PASSWD": true, "PASSPHRASE": true, "PWD": true,
	"SIG": true, "SIGNATURE": true, "SESSION": true,
}

// sensitiveName reports whether an environment variable, flag, header or
// query parameter name suggests that its value is a secret: it contains
// one of sensitiveEnvKeys or COOKIE, or one of its words (split at
// separators and camel-case boundaries) is in sensitiveWords.
func sensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range sensitiveEnvKeys {
		if strings.Contains(upper, s) {
			return true
		}
	}
	if strings.Contains(upper, "COOKIE") {
		return true
	}
	for _, w := range nameWords(name) {
		if sensitiveWords[strings.ToUpper(w)] {
			return true
		}
	}
	return false
}

// nameWords splits a name at non-alphanumeric separators and at a lower to
// upper case change: "DB_PASS" -> DB, PASS; "dbPass" -> db, Pass.
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
		case unicode.IsUpper(r) && unicode.IsLower(runes[i-1]):
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
	v = authScheme.ReplaceAllString(v, "${1}${2}"+redactedPlaceholder)
	return secretShapes.ReplaceAllString(v, redactedPlaceholder)
}

// redactArgValue redacts one argument, or the value of a --flag=value
// argument: a sensitive "Name: value" header, a sensitive NAME=value
// assignment, and anything redactValue removes.
func redactArgValue(a string) string {
	if m := headerArg.FindStringSubmatch(a); m != nil && !strings.HasPrefix(m[2], "//") && sensitiveName(m[1]) {
		return m[1] + ": " + redactedPlaceholder
	}
	if m := assignment.FindStringSubmatch(a); m != nil && m[2] != "" && sensitiveName(m[1]) {
		return m[1] + "=" + redactedPlaceholder
	}
	return redactValue(a)
}

// redactArgs redacts a server's command-line arguments. The value of a
// flag whose name suggests a secret is replaced, whether it follows the
// flag (--api-key x, also a value starting with a single dash) or is
// joined to it (--token=x); a --flag=value whose value is a sensitive
// header or NAME=value assignment (--header=Authorization: ..., --env=
// API_KEY=...) and a separate NAME=value argument (-e DB_PASS=...) are
// redacted too, as are secret-shaped values anywhere. Commands, package
// names and other arguments stay visible.
func redactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	valueIsSecret := false
	for i, a := range args {
		if valueIsSecret && !strings.HasPrefix(a, "--") {
			out[i] = redactedPlaceholder
			valueIsSecret = false
			continue
		}
		valueIsSecret = false
		if a == "--" || !strings.HasPrefix(a, "-") {
			out[i] = redactArgValue(a)
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		flag := strings.TrimLeft(name, "-")
		switch {
		case hasValue && sensitiveName(flag):
			out[i] = name + "=" + redactedPlaceholder
		case hasValue:
			out[i] = name + "=" + redactArgValue(value)
		default:
			valueIsSecret = sensitiveName(flag)
			out[i] = redactValue(a)
		}
	}
	return out
}

// redactHeaders masks every header whose name suggests a credential and
// redacts secret-shaped parts of the others.
func redactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if sensitiveName(k) {
			out[k] = redactedPlaceholder
		} else {
			out[k] = redactValue(v)
		}
	}
	return out
}
