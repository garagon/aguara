package intel

import (
	"regexp"
	"strings"
)

// maxPEP440Length bounds the input the canonicaliser looks at. Real
// versions are a few dozen bytes; anything longer is not a version a
// registry would publish, so it gets literal comparison only.
const maxPEP440Length = 256

// pep440Pattern is the version grammar from the PEP 440 appendix
// ("Parsing version strings with regular expressions"), the same
// pattern the packaging library uses, anchored and case-insensitive.
var pep440Pattern = regexp.MustCompile(`(?i)^\s*v?` +
	`(?:([0-9]+)!)?` + // epoch
	`([0-9]+(?:\.[0-9]+)*)` + // release
	`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]+)?)?` + // pre-release
	`(?:-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]+)?)?` + // post-release
	`(?:[-_.]?(dev)[-_.]?([0-9]+)?)?` + // development release
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?` + // local version label
	`\s*$`)

// PEP440Canonical returns the canonical form PEP 440 uses for version
// equality: spelling variants are normalised ("1.0RC1" and "1.0-rc.1"
// become "1rc1"), leading zeros are dropped from numeric components,
// and trailing zero release components are removed so that "1.0" and
// "1.0.0" compare equal, as the PEP's zero-padding rule requires.
//
// The local version label is kept. PyPI does not accept uploads with
// a local label, so "1.0+cpu" names a build from somewhere else and
// must not be treated as the registry release "1.0".
//
// ok is false for input that is not a valid PEP 440 version; callers
// fall back to literal comparison in that case.
func PEP440Canonical(v string) (string, bool) {
	if len(v) > maxPEP440Length {
		return "", false
	}
	m := pep440Pattern.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	var b strings.Builder
	if epoch := trimLeadingZeros(m[1]); epoch != "" && epoch != "0" {
		b.WriteString(epoch)
		b.WriteByte('!')
	}
	release := strings.Split(m[2], ".")
	for i := range release {
		release[i] = trimLeadingZeros(release[i])
	}
	for len(release) > 1 && release[len(release)-1] == "0" {
		release = release[:len(release)-1]
	}
	b.WriteString(strings.Join(release, "."))
	if m[3] != "" {
		switch strings.ToLower(m[3]) {
		case "a", "alpha":
			b.WriteString("a")
		case "b", "beta":
			b.WriteString("b")
		default: // c, rc, pre, preview
			b.WriteString("rc")
		}
		b.WriteString(numberOrZero(m[4]))
	}
	switch {
	case m[5] != "":
		b.WriteString(".post")
		b.WriteString(trimLeadingZeros(m[5]))
	case m[6] != "":
		b.WriteString(".post")
		b.WriteString(numberOrZero(m[7]))
	}
	if m[8] != "" {
		b.WriteString(".dev")
		b.WriteString(numberOrZero(m[9]))
	}
	if m[10] != "" {
		parts := strings.FieldsFunc(strings.ToLower(m[10]), func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
		for i, p := range parts {
			if isASCIIDigits(p) {
				parts[i] = trimLeadingZeros(p)
			}
		}
		b.WriteByte('+')
		b.WriteString(strings.Join(parts, "."))
	}
	return b.String(), true
}

// PEP440Equal reports whether two version strings name the same PyPI
// release: equal literally, or equal after PEP440Canonical.
func PEP440Equal(a, b string) bool {
	if a == b {
		return a != ""
	}
	ca, ok := PEP440Canonical(a)
	if !ok {
		return false
	}
	cb, ok := PEP440Canonical(b)
	return ok && ca == cb
}

func trimLeadingZeros(s string) string {
	if s == "" {
		return ""
	}
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}

func numberOrZero(s string) string {
	if s == "" {
		return "0"
	}
	return trimLeadingZeros(s)
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
