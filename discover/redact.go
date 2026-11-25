package discover

import (
	"regexp"
	"strings"

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

// authScheme matches the credential after an HTTP authorization scheme.
var authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=-]{4,}`)

// queryParam matches one name=value pair of a URL query.
var queryParam = regexp.MustCompile(`([?&])([^=&#\s]+)=([^&#\s]*)`)

// headerArg matches a "Name: value" argument such as the --header value
// of an MCP proxy.
var headerArg = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*:\s*(.+)$`)

// sensitiveName reports whether an environment variable, flag, header or
// query parameter name suggests that its value is a secret.
func sensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range sensitiveEnvKeys {
		if strings.Contains(upper, s) {
			return true
		}
	}
	return strings.Contains(upper, "COOKIE")
}

// redactValue removes secret-shaped parts of a value and keeps the rest:
// URL userinfo, sensitive query parameter values, the credential after an
// authorization scheme, and known token formats.
func redactValue(v string) string {
	if v == "" || v == redactedPlaceholder {
		return v
	}
	v = types.SanitizeURLUserinfo(v, redactedPlaceholder+"@")
	if strings.ContainsAny(v, "?&") {
		v = queryParam.ReplaceAllStringFunc(v, func(m string) string {
			p := queryParam.FindStringSubmatch(m)
			if p[3] == "" || p[3] == redactedPlaceholder || !sensitiveName(p[2]) {
				return m
			}
			return p[1] + p[2] + "=" + redactedPlaceholder
		})
	}
	v = authScheme.ReplaceAllString(v, "${1}${2}"+redactedPlaceholder)
	return secretShapes.ReplaceAllString(v, redactedPlaceholder)
}

// redactArgs redacts a server's command-line arguments: the value of a
// flag whose name suggests a secret (--token=x, --api-key x), the value
// of a sensitive "Name: value" header argument, and secret-shaped values
// anywhere.
func redactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	valueIsSecret := false
	for i, a := range args {
		if valueIsSecret && !strings.HasPrefix(a, "-") {
			out[i] = redactedPlaceholder
			valueIsSecret = false
			continue
		}
		valueIsSecret = false
		if name, _, ok := strings.Cut(a, "="); ok && strings.HasPrefix(name, "-") && sensitiveName(strings.TrimLeft(name, "-")) {
			out[i] = name + "=" + redactedPlaceholder
			continue
		}
		if m := headerArg.FindStringSubmatch(a); m != nil && !strings.Contains(a, "://") && sensitiveName(m[1]) {
			out[i] = m[1] + ": " + redactedPlaceholder
			continue
		}
		if strings.HasPrefix(a, "-") && sensitiveName(strings.TrimLeft(a, "-")) {
			valueIsSecret = true
		}
		out[i] = redactValue(a)
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
