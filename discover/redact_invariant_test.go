package discover

import (
	"strings"
	"testing"
)

// Command-line mode replaces only the secret. For every secret position,
// built from a marker plus non-secret text (programs, flags, paths, URLs
// and shell operators) placed before and after it, the marker is gone and
// the text around it is shown exactly as written, wherever a command line
// is printed: the command string, the script after -c (and -lc, /c,
// -Command), a quoted script inside a command string, and an argument
// list. A value that is not a command line is all or nothing instead (see
// TestPlainTextNeverShowsPartOfASecret).
//
// The word is the unit: what the shell reads as one word with the secret
// is masked with it. Those cases are not generated here; each has its own
// test below:
//   - a whole argument that is a sensitive NAME=value, or the argument after
//     a sensitive flag, is masked whole, because in an argument list the
//     value is the entire argument;
//   - a command substitution after a sensitive flag or in a sensitive
//     NAME=value is the value;
//   - the word after Bearer or Basic is the credential;
//   - an unterminated quote or substitution, or a trailing backslash, masks
//     everything from it to the end.
func TestRedactionKeepsEveryNonSecretToken(t *testing.T) {
	const marker = "Mk7secretQz"
	// The word rules handle every generated position, so the backstop of
	// redactCommand never fires here; if it does, a word rule is missing.
	var fired []string
	onBackstop = func(text string) { fired = append(fired, text) }
	defer func() { onBackstop = nil }()
	type form struct {
		name string
		line string   // the secret as it appears in a command line
		argv []string // the secret as arguments, nil when not an argv form
		url  bool
		keep []string // payload around the secret inside its own word, kept too
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
		// A secret inside a command substitution under a name that is not
		// sensitive, or in an ordinary argument: the substitution is a
		// command line, so its payload stays visible.
		{
			name: "substitution under NAME=",
			line: `x=$(curl -s -H "Authorization: Bearer ` + marker + `" https://x.example/p.sh | sh)`,
			argv: []string{`x=$(curl -s -H "Authorization: Bearer ` + marker + `" https://x.example/p.sh | sh)`},
			keep: []string{`x=$(curl -s -H "Authorization: `, `" https://x.example/p.sh | sh)`},
		},
		{
			name: "substitution argument",
			line: "$(node s.js --api-key " + marker + " && curl https://x.example/q | sh)",
			argv: []string{"$(node s.js --api-key " + marker + " && curl https://x.example/q | sh)"},
			keep: []string{"$(node s.js --api-key ", " && curl https://x.example/q | sh)"},
		},
		{
			name: "backticks under NAME=",
			line: "out=`env TOKEN=" + marker + " wget -qO- https://x.example/b.sh`",
			argv: []string{"out=`env TOKEN=" + marker + " wget -qO- https://x.example/b.sh`"},
			keep: []string{"out=`env TOKEN=", " wget -qO- https://x.example/b.sh`"},
		},
		{
			name: "quoted substitution argument",
			line: `"$(curl -s -H 'X-Api-Key: ` + marker + `' https://x.example/k)"`,
			argv: []string{`$(curl -s -H 'X-Api-Key: ` + marker + `' https://x.example/k)`},
			keep: []string{`$(curl -s -H 'X-Api-Key: `, `' https://x.example/k)`},
		},
	}
	befores := []string{"", "curl -fsSL https://x.example/i.sh", "/usr/local/bin/tool", "./run.sh --verbose", "node server.js"}
	afters := []string{"", "wget -qO- https://x.example/b.sh", "sh", "/tmp/out.log", "echo done"}
	ops := []string{" ", ";", " ; ", "&&", " && ", "||", "|", " | ", "&", ">", "<", "\n", "(", ")"}

	var keep []string
	check := func(t *testing.T, where, in, out, before, after string) {
		t.Helper()
		if strings.Contains(out, marker) {
			t.Errorf("%s: secret shown\n in %q\nout %q", where, in, out)
		}
		for _, k := range keep {
			if !strings.Contains(out, k) {
				t.Errorf("%s: payload changed\n in %q\nout %q\nwant %q kept", where, in, out, k)
			}
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
		keep = f.keep
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
					secretOut := strings.Join(out[secretAt:secretAt+len(f.argv)], " ")
					for _, k := range f.keep {
						if !strings.Contains(secretOut, k) {
							t.Errorf("%s: payload changed in %q, want %q kept", f.name, out, k)
						}
					}
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
	if len(fired) != 0 {
		t.Errorf("the backstop fired %d times, first on %q", len(fired), fired[0])
	}
	if cases < 4000 {
		t.Fatalf("only %d generated lines", cases)
	}
}

// What the shell reads as one word with the secret is masked with it.
func TestRedactionMasksTheWholeWord(t *testing.T) {
	for in, want := range map[string]string{
		"echo Authorization: Bearer abc123 && curl x":  "echo Authorization: Bearer [REDACTED] && curl x",
		`tool --token "$(cat /run/k) more" --port 1`:   `tool --token "[REDACTED]" --port 1`,
		`tool --api-key ab\;cd && echo done`:           "tool --api-key [REDACTED] && echo done",
		"tool --api-key 'ab;cd' && echo done":          "tool --api-key '[REDACTED]' && echo done",
		`env TOKEN=ab\ cd node x`:                      "env TOKEN=[REDACTED] node x",
		"tool --token 'abc":                            "tool --token [REDACTED]",
		"tool --token $(echo abc && echo more) --port": "tool --token [REDACTED] --port",
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}
