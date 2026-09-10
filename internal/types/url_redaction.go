package types

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Match only the authority prefix, ending at its last @. Do not require a
// valid URL: diagnostics can contain malformed URLs alongside a real finding.
// Paths, queries, fragments and surrounding quoted source are not authority.
var urlUserinfo = regexp.MustCompile("[A-Za-z][A-Za-z0-9+.-]*://[^/\\s?#\"<>`]*@")
var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)
var jsonStringToken = regexp.MustCompile(`"(?:[^"\\\r\n]|\\[^\r\n])*"`)

// StripURLUserinfo handles a complete decoded dependency value, rather than
// quoted source text. Apostrophes and other raw userinfo bytes must not make
// the sanitizer less permissive than dependency classification.
func StripURLUserinfo(value string) string {
	i := strings.Index(value, "://")
	if i < 0 || !urlScheme.MatchString(value[:i]) {
		return value
	}
	start := i + 3
	end := len(value)
	if n := strings.IndexAny(value[start:], "/?#"); n >= 0 {
		end = start + n
	}
	if at := strings.LastIndexByte(value[start:end], '@'); at >= 0 {
		return value[:start] + value[start+at+1:]
	}
	return value
}

// SanitizeURLUserinfo replaces complete URL userinfo prefixes in text. The
// replacement includes its own @ when a caller wants to keep a placeholder.
// Other URL components and their original escaping are preserved.
func SanitizeURLUserinfo(text, replacement string) string {
	// Report context can retain JSON source escapes even when an analyzer
	// consumed the decoded URL. Decode complete string tokens, never guess
	// at escape spellings or change the scanned source itself.
	if strings.Contains(text, `\`) {
		text = jsonStringToken.ReplaceAllStringFunc(text, func(token string) string {
			var decoded string
			if json.Unmarshal([]byte(token), &decoded) != nil {
				return token
			}
			safe := sanitizeLiteralURLUserinfo(decoded, replacement)
			if safe == decoded {
				return token
			}
			encoded, _ := json.Marshal(safe)
			return string(encoded)
		})
	}
	return sanitizeLiteralURLUserinfo(text, replacement)
}

func sanitizeLiteralURLUserinfo(text, replacement string) string {
	if !strings.Contains(text, "://") || !strings.Contains(text, "@") {
		return text
	}
	return urlUserinfo.ReplaceAllStringFunc(text, func(prefix string) string {
		return prefix[:strings.Index(prefix, "://")+3] + replacement
	})
}
