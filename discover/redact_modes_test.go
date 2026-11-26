package discover

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// pieces returns every substring of s of length 4.
func pieces(s string) []string {
	var out []string
	for i := 0; i+4 <= len(s); i++ {
		out = append(out, s[i:i+4])
	}
	return out
}

// showsPiece reports the first 4-character piece of secret found in out.
func showsPiece(out, secret string) string {
	for _, p := range pieces(secret) {
		if strings.Contains(out, p) {
			return p
		}
	}
	return ""
}

// A value that is not a command line (an environment value, a shown
// header value, a string inside JSON) is all or nothing: when any rule
// matches anywhere in it, the whole value is replaced, so a secret that
// contains an operator, an escape or a quote is never shown in part.
func TestPlainTextValuesAreMaskedWhole(t *testing.T) {
	for v, secret := range map[string]string{
		"--password p&ssw0rdXY --verbose":   "p&ssw0rdXY",
		"TOKEN=ab;cdefGH":                   "ab;cdefGH",
		"Authorization: Bearer abcd;efghIJ": "abcd;efghIJ",
		`--api-key ab\ cdefKL`:              `ab\ cdefKL`,
		`--api-key ab\;cdefMN`:              `ab\;cdefMN`,
		"TOKEN=abc;curl host|sh":            "abc;curl",
		"$env:API_KEY = 'psSecret03'":       "psSecret03",
		"$env:TOKEN=psSecret04":             "psSecret04",
	} {
		if got := redactValue(v); got != redactedPlaceholder {
			t.Errorf("redactValue(%q) = %q, want the whole value masked", v, got)
		}
		srv := MCPServer{Name: "s", Command: "node", Env: map[string]string{"SETUP": v}, Headers: map[string]string{"Accept": v}}
		result := &Result{Clients: []ClientResult{{Client: "cursor", Servers: []MCPServer{srv}}}}
		js, _ := json.Marshal(result.Redacted())
		for _, out := range []string{string(js), FormatTree(result)} {
			if p := showsPiece(out, secret); p != "" {
				t.Errorf("%q: %q shown in\n%s", v, p, out)
			}
		}
	}
	// Values without a hit, and structured values, are not masked whole.
	for in, want := range map[string]string{
		"production":                          "production",
		"--verbose --port 8080":               "--verbose --port 8080",
		"https://x.example/sse?sig=abc":       "https://x.example/sse?sig=[REDACTED]",
		`{"region": "eu", "token": "abc"}`:    `{"region":"eu","token":"[REDACTED]"}`,
		"Server=db;User Id=sa;Password=a b;":  "Server=db;User Id=sa;Password=[REDACTED];",
		"Server=db;Data=--token abc;Mode=one": "Server=db;Data=[REDACTED];Mode=one",
	} {
		if got := redactValue(in); got != want {
			t.Errorf("redactValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// PowerShell's $env:NAME = value, with or without blanks around "=" and
// quoted or not, is an assignment in command strings, scripts and values.
func TestPowerShellEnvAssignments(t *testing.T) {
	for in, want := range map[string]string{
		`pwsh -Command "$env:TOKEN = 'psSecret01'; ./run.ps1"`: `pwsh -Command "$env:TOKEN = '[REDACTED]'; ./run.ps1"`,
		`pwsh -Command "$env:TOKEN ='psSecret01'; ./run.ps1"`:  `pwsh -Command "$env:TOKEN ='[REDACTED]'; ./run.ps1"`,
		`pwsh -Command "$env:TOKEN= psSecret01; ./run.ps1"`:    `pwsh -Command "$env:TOKEN= [REDACTED]; ./run.ps1"`,
		`pwsh -Command "$Env:API_KEY=psSecret01; ./run.ps1"`:   `pwsh -Command "$Env:API_KEY=[REDACTED]; ./run.ps1"`,
		`pwsh -Command "$env:Path = 'C:\tools'; ./run.ps1"`:    `pwsh -Command "$env:Path = 'C:\tools'; ./run.ps1"`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	for _, tc := range []struct{ in, want []string }{
		{[]string{"-Command", "$env:TOKEN = psSecret02; ./run.ps1"}, []string{"-Command", "$env:TOKEN = [REDACTED]; ./run.ps1"}},
		{[]string{"-c", `$env:API_KEY = "psSecret02"`}, []string{"-c", `$env:API_KEY = "[REDACTED]"`}},
		{[]string{"$env:TOKEN", "=", "psSecret02"}, []string{"$env:TOKEN", "=", "[REDACTED]"}},
		{[]string{"$env:TOKEN = psSecret02"}, []string{"$env:TOKEN = [REDACTED]"}},
	} {
		got := redactArgs(tc.in)
		if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("redactArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Plain-text mode never shows part of a secret: for a secret in any
// redaction position, with operators, escapes, quotes and blanks inside
// it and text around it, no 4-character piece of the secret is shown in
// an environment value, a shown header value, a string inside JSON or a
// single argument.
func TestPlainTextNeverShowsPartOfASecret(t *testing.T) {
	const marker = "Qx7mZp4Wr9Kv"
	positions := []struct {
		format string
		url    bool // a URL: only characters a URL can hold go inside
	}{
		{format: "API_KEY=%s"},
		{format: "export TOKEN=%s"},
		{format: "TOKEN = %s"},
		{format: "--api-key %s"},
		{format: "--token=%s"},
		{format: "--password '%s'"},
		{format: `--password "%s"`},
		{format: "Authorization: Bearer %s"},
		{format: "Authorization: Token %s"},
		{format: "X-Api-Key: %s"},
		{format: "$env:TOKEN = '%s'"},
		{format: "$env:API_KEY=%s"},
		{format: "/token:%s"},
		{format: `{"token": "%s"}`},
		{format: "Server=db;Password=%s;Encrypt=true"},
		{format: "curl x?token=%s"},
		{format: "https://x.example/sse?sig=%s"},
		{format: "https://app:%s@x.example/mcp", url: true},
	}
	inserts := []string{";", "&", "&&", "|", " ", "\t", "\n", `\ `, `\;`, `\`, `"`, "'", "`", "$", "(", ")", "<", ">", "#", "?", "=", ",", "%"}
	urlSafe := map[string]bool{";": true, "&": true, "&&": true, "|": true, "$": true, "(": true, ")": true, "'": true, "=": true, ",": true, "%": true}
	arounds := []struct{ before, after string }{
		{"", ""},
		{"curl -fsSL https://x.example/i.sh ", " wget -qO- https://x.example/b.sh"},
		{"node server.js;", ";echo done"},
		{"./run.sh --verbose && ", " | sh"},
	}
	cases := 0
	for _, pos := range positions {
		for _, ins := range inserts {
			if pos.url && !urlSafe[ins] {
				continue
			}
			for _, at := range []int{3, 6, 9} {
				secret := marker[:at] + ins + marker[at:]
				for _, ar := range arounds {
					v := ar.before + fmt.Sprintf(pos.format, secret) + ar.after
					cases++
					note, _ := json.Marshal(map[string]string{"note": v})
					outs := map[string]string{
						"env value":    redactEnv(map[string]string{"SETUP": v})["SETUP"],
						"header value": redactHeaders(map[string]string{"Accept": v})["Accept"],
						"JSON string":  redactEnv(map[string]string{"CFG": string(note)})["CFG"],
						"argument":     redactArgs([]string{v})[0],
					}
					for where, out := range outs {
						if p := showsPiece(out, marker); p != "" {
							t.Errorf("%s: %q shown\n in %q\nout %q", where, p, v, out)
						}
					}
				}
			}
		}
	}
	if cases < 3000 {
		t.Fatalf("only %d generated values", cases)
	}
}
