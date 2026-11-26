package discover

import (
	"strings"
	"testing"
)

// Redaction may only replace secret values. For every secret position,
// built from a marker plus non-secret text (programs, flags, paths, URLs
// and shell operators) placed before and after it, the marker is gone and
// the text around it is shown exactly as written, in each place a command
// line is printed: the command string, the script after -c (and -lc, /c,
// -Command), a quoted -c script inside a command string, an environment
// value, and an argument list.
//
// Where a value cannot be delimited, the secret wins and the smallest span
// that holds it is masked. Those cases are not generated here; each has its
// own test below:
//   - a whole argument that is a sensitive NAME=value, or the argument after
//     a sensitive flag, is masked whole, because in an argument list the
//     value is the entire argument;
//   - in a value whose every ";"-separated part is Name=value (a
//     connection string), a sensitive part is masked to the next ";";
//   - a URL in text runs to a blank, a quote, a shell operator or "&&", so
//     text joined to a secret query value by a single "&" is read as part
//     of the query and masked; a value without blanks that starts with a
//     URL is one URL;
//   - the word after an authorization scheme (Bearer, Basic, Token) is a
//     credential;
//   - an unterminated quote masks everything from the quote to the end.
func TestRedactionKeepsEveryNonSecretToken(t *testing.T) {
	const marker = "Mk7secretQz"
	type form struct {
		name string
		line string   // the secret as it appears in a command line
		argv []string // the secret as arguments, nil when not an argv form
		url  bool
	}
	forms := []form{
		{name: "NAME=value", line: "API_KEY=" + marker, argv: []string{"API_KEY=" + marker}},
		{name: "export NAME=value", line: "export TOKEN=" + marker},
		{name: "flag value", line: "--api-key " + marker, argv: []string{"--api-key", marker}},
		{name: "flag=value", line: "--token=" + marker, argv: []string{"--token=" + marker}},
		{name: "double-quoted assignment", line: `DB_PASSWORD="` + marker + `"`},
		{name: "single-quoted flag value", line: "--password '" + marker + "'"},
		{name: "header", line: `-H "Authorization: Bearer ` + marker + `"`, argv: []string{"-H", "Authorization: Bearer " + marker}},
		{name: "query value", line: "https://x.example/sse?sig=" + marker, argv: []string{"https://x.example/sse?sig=" + marker}, url: true},
		{name: "userinfo", line: "https://app:" + marker + "@x.example/mcp", argv: []string{"https://app:" + marker + "@x.example/mcp"}, url: true},
		{name: "PowerShell env", line: "$env:API_KEY='" + marker + "'"},
	}
	befores := []string{"", "curl -fsSL https://x.example/i.sh", "/usr/local/bin/tool", "./run.sh --verbose", "node server.js"}
	afters := []string{"", "wget -qO- https://x.example/b.sh", "sh", "/tmp/out.log", "echo done"}
	ops := []string{" ", ";", " ; ", "&&", " && ", "||", "|", " | ", "&", ">", "<", "\n", "(", ")"}

	check := func(t *testing.T, where, in, out, before, after string) {
		t.Helper()
		if strings.Contains(out, marker) {
			t.Errorf("%s: secret shown\n in %q\nout %q", where, in, out)
		}
		if before != "" && !strings.Contains(out, before) {
			t.Errorf("%s: text before the secret changed\n in %q\nout %q\nwant %q kept", where, in, out, before)
		}
		if after != "" && !strings.Contains(out, after) {
			t.Errorf("%s: text after the secret changed\n in %q\nout %q\nwant %q kept", where, in, out, after)
		}
	}

	cases := 0
	for _, f := range forms {
		for bi, b := range befores {
			// Each prefix is paired with two suffixes, so every prefix and
			// suffix appears twice, empty ones included.
			for _, a := range []string{afters[bi], afters[(bi+2)%len(afters)]} {
				for i, op1 := range ops {
					// Every operator appears on both sides, each paired with
					// three others, which keeps the run short.
					for _, op2 := range []string{ops[i], ops[(i+5)%len(ops)], ops[(i+9)%len(ops)]} {
						before, after := "", ""
						if b != "" {
							before = b + op1
						}
						if a != "" {
							after = op2 + a
						}
						line := before + f.line + after
						cases++

						check(t, f.name+" in a command", line, redactCommand(line), before, after)
						// The script flags share one code path; each line uses
						// one of them in turn.
						flag := []string{"-c", "-lc", "-ec", "/c", "-Command"}[cases%5]
						out := redactArgs([]string{flag, line})
						if out[0] != flag {
							t.Errorf("%s: flag changed to %q", flag, out[0])
						}
						check(t, f.name+" in a "+flag+" script", line, out[1], before, after)
						if !strings.Contains(line, "'") {
							cmd := "sh -c '" + line + "'"
							check(t, f.name+" in a quoted script", cmd, redactCommand(cmd), "sh -c '"+before, after+"'")
						}
						if !strings.ContainsAny(line, "\"$") {
							cmd := `bash -lc "` + line + `"`
							check(t, f.name+" in a double-quoted script", cmd, redactCommand(cmd), `bash -lc "`+before, after+`"`)
						}
						// In text, a single "&" right after a URL is a query
						// separator, and a value without blanks that starts
						// with a URL is one URL (see above).
						if !(f.url && (strings.HasPrefix(op2, "&") && !strings.HasPrefix(op2, "&&") || !strings.ContainsAny(line, " \t\n"))) {
							env := redactEnv(map[string]string{"SETUP": line})["SETUP"]
							check(t, f.name+" in an environment value", line, env, before, after)
						}
					}
				}
				if f.argv == nil {
					continue
				}
				// Argument lists: every non-secret argument is unchanged.
				for _, op := range []string{"", ";", "&&", "|", ">", "("} {
					var args []string
					if b != "" {
						args = append(args, strings.Fields(b)...)
						if op != "" {
							args = append(args, op)
						}
					}
					secretAt := len(args)
					args = append(args, f.argv...)
					if a != "" {
						if op != "" {
							args = append(args, op)
						}
						args = append(args, strings.Fields(a)...)
					}
					out := redactArgs(args)
					for i := range args {
						if i >= secretAt && i < secretAt+len(f.argv) {
							if strings.Contains(out[i], marker) {
								t.Errorf("%s: secret shown in %q", f.name, out)
							}
							continue
						}
						if out[i] != args[i] {
							t.Errorf("%s: argument %d %q changed to %q in %q", f.name, i, args[i], out[i], args)
						}
					}
				}
			}
		}
	}
	if cases < 4000 {
		t.Fatalf("only %d generated lines", cases)
	}
}

// The cases where the secret cannot be delimited: the smallest span that
// holds it is masked.
func TestRedactionMasksUndelimitedValues(t *testing.T) {
	for in, want := range map[string]string{
		// A connection string: the value runs to the next ";".
		"Server=db;User Id=sa;Password=correct horse && more;Encrypt=true": "Server=db;User Id=sa;Password=[REDACTED];Encrypt=true",
		// A single "&" after a secret query value belongs to the query.
		"curl https://x.example/sse?sig=abc&wget": "curl https://x.example/sse?sig=[REDACTED]&[REDACTED]",
		// One URL without blanks: ";" separates query parameters.
		"https://x.example/sse?sig=abc;rm": "https://x.example/sse?sig=[REDACTED];[REDACTED]",
		// The word after an authorization scheme is the credential.
		"Authorization: Bearer abc123 && curl x": "Authorization: Bearer [REDACTED] && curl x",
	} {
		if got := redactValue(in); got != want {
			t.Errorf("redactValue(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}
