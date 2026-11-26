package discover

import (
	"encoding/json"
	"strings"
	"testing"
)

// v029Masked is the environment rule of v0.29.0: a name containing one
// of these, in any letter case, had its value masked. Discovery must never
// show a value that rule hid.
func v029Masked(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH", "PRIVATE", "API_KEY", "APIKEY"} {
		if strings.Contains(upper, s) {
			return true
		}
	}
	return false
}

// The names a review found printed in clear, plus names that were masked
// already.
var v029Names = []string{
	"SSHKEYB64", "KEYB64", "KEYMATERIAL", "TLSKEYDATA", "SIGNINGKEYPEM", "JWTKEYFILE",
	"KEYSTORE", "MASTERKEYS", "PRIVATEDATA", "AUTHDATA", "AUTHHEADER", "aPi_KeY",
	"API_TOKEN", "DB_PASSWORD", "MY_SECRET",
}

func TestEnvMaskingCoversTheV029Names(t *testing.T) {
	for _, name := range v029Names {
		env := redactEnv(map[string]string{name: "plainvalue"})
		if env[name] != "***REDACTED***" {
			t.Errorf("env %s = %q, want it masked as in v0.29.0", name, env[name])
		}
	}
}

// generatedNames combines prefixes, sensitive words in several letter
// cases, and suffixes, so odd case or missing separators cannot hide a
// word from the environment rule.
func generatedNames() []string {
	words := []string{"key", "token", "secret", "password", "credential", "auth", "private", "apikey", "api_key"}
	prefixes := []string{"", "MY_", "db", "Ssh", "x-", "signing"}
	suffixes := []string{"", "_FILE", "b64", "DATA", "Store", "s", "-pem", "HEADER"}
	cases := []func(string) string{
		strings.ToUpper, strings.ToLower,
		func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		func(s string) string { // aLtErNaTiNg
			b := []byte(s)
			for i := range b {
				if i%2 == 1 && b[i] >= 'a' && b[i] <= 'z' {
					b[i] -= 'a' - 'A'
				}
			}
			return string(b)
		},
	}
	var names []string
	for _, w := range words {
		for _, c := range cases {
			for _, p := range prefixes {
				for _, s := range suffixes {
					names = append(names, p+c(w)+s)
				}
			}
		}
	}
	return names
}

func TestEnvMaskingIsNeverWeakerThanV029(t *testing.T) {
	names := append(generatedNames(), v029Names...)
	failed := 0
	for _, name := range names {
		if !v029Masked(name) {
			continue
		}
		red := redactEnv(map[string]string{name: "plainvalue"})
		if red[name] != "***REDACTED***" {
			failed++
			if failed <= 10 {
				t.Errorf("env %s is shown, v0.29.0 masked it", name)
			}
		}
		// The same name as an embedded JSON key or a NAME=value
		// assignment is never shown either.
		js := redactValue(`{"` + name + `": "plainvalue"}`)
		if strings.Contains(js, "plainvalue") {
			t.Errorf("JSON key %s shown: %s", name, js)
		}
		if strings.HasPrefix(name, "x-") || strings.ContainsAny(name[:1], "0123456789") {
			continue // not a shell variable name
		}
		if got := redactArgValue(name + "=plainvalue"); strings.Contains(got, "plainvalue") {
			t.Errorf("assignment %s shown: %s", name, got)
		}
	}
	if failed > 10 {
		t.Errorf("%d names in total", failed)
	}
}

// Flags keep precise word matching, so --keyboard stays visible, but odd
// letter case does not hide a sensitive word.
func TestFlagNamesAreCaseInsensitive(t *testing.T) {
	got := redactArgs([]string{"--ApI-KeY", "plainvalue", "--TOKEN", "v2", "--keyboard", "us"})
	want := []string{"--ApI-KeY", "[REDACTED]", "--TOKEN", "[REDACTED]", "--keyboard", "us"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("redactArgs = %v, want %v", got, want)
	}
	js, _ := json.Marshal(got)
	if strings.Contains(string(js), "plainvalue") {
		t.Error("value shown")
	}
}
