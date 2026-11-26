package intel

import (
	"regexp"
	"strconv"
	"strings"
)

// maxVersionKeyLength bounds the input the per-ecosystem canonicalisers
// look at. Published versions are a few dozen bytes; anything longer is
// compared literally only.
const maxVersionKeyLength = 256

// canonicalVersion returns the form an ecosystem's own tooling compares
// versions in, for the ecosystems where two spellings name one release.
// ok is false when the ecosystem compares versions as literal strings, or
// when v is not a valid version in that ecosystem's grammar; the caller
// then relies on literal equality alone, so an unusual string can never
// match more than itself.
//
//   - PyPI: PEP 440 equality (PEP440Canonical).
//   - Go: the module version without the leading "v" and without the
//     "+incompatible" suffix (goVersionKey).
//   - Packagist: Composer's VersionParser::normalize (composerNormalize).
//   - NuGet: NuGet's normalized version with a case-folded pre-release
//     label (nugetNormalize).
//
// npm, crates.io, RubyGems and Maven compare literally: their lockfiles
// record the version string exactly as the registry published it, and the
// intelligence records the same string.
func canonicalVersion(ecosystem, v string) (string, bool) {
	if v == "" || len(v) > maxVersionKeyLength {
		return "", false
	}
	switch ecosystem {
	case EcosystemPyPI:
		return PEP440Canonical(v)
	case EcosystemGo:
		return goVersionKey(v)
	case EcosystemPackagist:
		return composerNormalize(v)
	case EcosystemNuGet:
		return nugetNormalize(v)
	default:
		return "", false
	}
}

// semverCore is a semantic version without build metadata: three numeric
// components without leading zeros and an optional pre-release of
// dot-separated identifiers (SemVer 2.0.0, items 2 and 9). Numeric
// pre-release identifiers must not have leading zeros either.
var semverCore = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$`)

// goVersionKey returns the comparison key for a Go module version.
//
// The Go Modules Reference ("Versions") spells every module version as
// "v" followed by a semantic version, which is how go.mod and go.sum write
// it, while OSV Go records (the Go vulnerability database and GitHub
// advisories alike) list the same versions without the "v". A major
// version of 2 or more published from a module path without a /vN suffix
// carries the "+incompatible" suffix ("Compatibility with non-module
// repositories"); it names the same tag, v2.0.0+incompatible being the
// v2.0.0 tag, so it is not part of the key. A module path cannot have
// both spellings of one version.
//
// Anything else must be equal: the numeric components, the pre-release
// (so a pseudo-version such as v0.0.0-20210510213326-e313ffa8abf6 only
// equals itself, never a tagged release) and the letter case. Go accepts
// no build metadata other than +incompatible in a module version, and no
// shorthand such as v1.2, so such input gets literal comparison only.
//
// "+incompatible" is only valid on a major version of 2 or more; on v0 or
// v1 it is not a Go version, so such input is compared literally too.
func goVersionKey(v string) (string, bool) {
	s := strings.TrimPrefix(v, "v")
	if core, ok := strings.CutSuffix(s, "+incompatible"); ok {
		if strings.HasPrefix(core, "0.") || strings.HasPrefix(core, "1.") {
			return "", false
		}
		s = core
	}
	if !semverCore.MatchString(s) {
		return "", false
	}
	return s, true
}

// composerClassical is Composer's classical-version pattern from
// VersionParser::normalize: up to four numeric parts with an optional
// leading "v", followed by $modifierRegex. Like Composer, it matches case
// insensitively.
var composerClassical = regexp.MustCompile(`(?i)^v?([0-9]{1,5})(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?` + composerModifier + `$`)

// composerDate is the date(time) branch of VersionParser::normalize, tried
// when the classical pattern does not match: a four-digit year followed by
// up to six two-digit groups and two short groups, each optionally after
// ".", ":" or "-", and the same modifiers.
var composerDate = regexp.MustCompile(`(?i)^v?([0-9]{4}(?:[.:-]?[0-9]{2}){1,6}(?:[.:-]?[0-9]{1,3}){0,2})` + composerModifier + `$`)

// composerModifier is VersionParser::$modifierRegex: a stability with an
// optional number, and an optional "dev" suffix.
const composerModifier = `[._-]?(?:(stable|beta|b|RC|alpha|a|patch|pl|p)((?:[.-]?[0-9]+)*)?)?([.-]?dev)?`

// composerNonDigit is the `{\D}` the date branch replaces with ".".
var composerNonDigit = regexp.MustCompile(`[^0-9]`)

// composerNormalize ports Composer's VersionParser::normalize
// (composer/semver), which is how Composer decides that two version
// strings are the same version: "v1.2.3", "1.2.3" and "1.2.3.0" all
// normalise to "1.2.3.0"; "1.0.0-RC1", "1.0.0-rc1" and "1.0.0RC1" to
// "1.0.0.0-RC1"; a date version "v20200101" or "2020-01-01" to
// "20200101" or "2020.01.01". composer.lock records the tag as written
// (with or without "v") while advisories may list either spelling.
//
// As in Composer: surrounding whitespace is trimmed, a branch ("dev-x",
// any letter case of the prefix) becomes "dev-" plus the name, build
// metadata is stripped, and then the classical and the date patterns are
// tried in that order. Other branch forms ("2.x-dev") are compared
// literally.
func composerNormalize(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) >= 4 && strings.EqualFold(v[:4], "dev-") {
		return "dev-" + v[4:], true
	}
	if i := strings.IndexByte(v, '+'); i > 0 {
		v = v[:i]
	}
	var b strings.Builder
	var mod []string // stability, number and dev groups
	if m := composerClassical.FindStringSubmatch(v); m != nil {
		b.WriteString(m[1])
		for _, part := range m[2:5] {
			if part == "" {
				part = ".0"
			}
			b.WriteString(part)
		}
		mod = m[5:8]
	} else if m := composerDate.FindStringSubmatch(v); m != nil {
		b.WriteString(composerNonDigit.ReplaceAllString(m[1], "."))
		mod = m[2:5]
	} else {
		return "", false
	}
	if mod[0] != "" {
		if mod[0] == "stable" {
			return b.String(), true
		}
		b.WriteByte('-')
		b.WriteString(composerExpandStability(mod[0]))
		b.WriteString(strings.TrimLeft(mod[1], ".-"))
	}
	if mod[2] != "" {
		b.WriteString("-dev")
	}
	return b.String(), true
}

// composerExpandStability is VersionParser::expandStability.
func composerExpandStability(s string) string {
	switch s = strings.ToLower(s); s {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "p", "pl":
		return "patch"
	case "rc":
		return "RC"
	default:
		return s
	}
}

// nugetVersion is NuGet's version grammar: one to four numeric parts, an
// optional pre-release label of dot-separated identifiers and optional
// build metadata.
var nugetVersion = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// nugetNormalize returns the comparison form NuGet uses for a version
// ("Package versioning" in the NuGet documentation): only the major part
// is required and missing parts are zero, so 1, 1.0, 1.0.0 and 1.0.0.0
// are equal; leading zeros are removed; a zero fourth part is omitted;
// build metadata is removed; and pre-release labels compare case
// insensitively, so 1.0.0-alpha equals 1.0.0-Alpha. nuget.org treats
// versions the same way, so two of these spellings cannot be different
// packages.
func nugetNormalize(v string) (string, bool) {
	m := nugetVersion.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	parts := strings.Split(m[1], ".")
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return "", false
		}
		parts[i] = strconv.FormatUint(n, 10)
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	if len(parts) == 4 && parts[3] == "0" {
		parts = parts[:3]
	}
	out := strings.Join(parts, ".")
	if m[2] != "" {
		out += "-" + strings.ToLower(m[2])
	}
	return out, true
}
