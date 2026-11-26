package discover

import (
	"strings"
	"testing"
)

// Pairs that are not shell syntax (Name: value, Token value, NAME = value)
// are found by the word rules in every command-line context.
func TestNonShellPairsInCommandLines(t *testing.T) {
	const secret = "qzS3cretA1"
	for _, form := range []string{"password: " + secret, "X-Api-Key: " + secret, "Token " + secret, "API_KEY = " + secret, "Authorization: Bearer " + secret, "Authorization: Token " + secret, "API_KEY =" + secret} {
		line := "login " + form + " --verbose"
		outs := map[string]string{
			"command":     redactCommand(line),
			"-c script":   redactArgs([]string{"-c", line})[1],
			"--exec":      redactArgs([]string{"--exec", line})[1],
			"eval":        redactCommand(`eval "` + line + `"`),
			"here-string": redactCommand(`bash <<< "` + line + `"`),
			"echo | sh":   redactCommand(`echo "` + line + `" | sh`),
			"$( )":        redactCommand("x=$(" + line + ")"),
		}
		for where, out := range outs {
			if p := showsPiece(out, secret); p != "" {
				t.Errorf("%s: %q: %q shown in %q", where, form, p, out)
			}
			if !strings.Contains(out, "login ") || !strings.Contains(out, " --verbose") {
				t.Errorf("%s: %q: the command around the secret changed: %q", where, form, out)
			}
		}
	}
	for in, want := range map[string]string{
		"login password: qzS3cretA1 --verbose":             "login password: [REDACTED] --verbose",
		"login Token qzS3cretA1 --verbose":                 "login Token [REDACTED] --verbose",
		"login API_KEY = qzS3cretA1 --verbose":             "login API_KEY = [REDACTED] --verbose",
		"login Authorization: Bearer qzS3cretA1 --verbose": "login Authorization: Bearer [REDACTED] --verbose",
		"login TOKEN= qzS3cretA1 --verbose":                "login TOKEN= [REDACTED] --verbose",
		"docker run -e GITHUB_TOKEN ghcr.io/github/server": "docker run -e GITHUB_TOKEN ghcr.io/github/server",
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// A here-string is a command line only for a shell; for any other program
// it is one plain value.
func TestHereStringOnlyToAShell(t *testing.T) {
	for in, want := range map[string]string{
		`cat <<< "TOKEN=ab;qzS3cretA2"`:              `cat <<< "[REDACTED]"`,
		`grep x <<< "API_KEY=ab qzS3cretA3"`:         `grep x <<< "[REDACTED]"`,
		`bash <<< "TOKEN=qzS3cretA3 node server.js"`: `bash <<< "TOKEN=[REDACTED] node server.js"`,
		`cat <<< "hello world"`:                      `cat <<< "hello world"`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// Of the long options, only --exec is known to take a shell command line;
// the value of --command, --cmd, --run and --shell-command is one value.
func TestOnlyExecTakesACommandLine(t *testing.T) {
	for _, opt := range []string{"--command", "--cmd", "--run", "--shell-command"} {
		value := "login --password p&ssqzS3cretA4"
		if got := redactArgs([]string{"tool", opt, value}); got[2] != redactedPlaceholder {
			t.Errorf("%s value = %q, want it masked whole", opt, got[2])
		}
		if got := redactArgs([]string{"tool", opt + "=" + value}); got[1] != opt+"="+redactedPlaceholder {
			t.Errorf("%s= value = %q, want it masked whole", opt, got[1])
		}
	}
	if got := redactArgs([]string{"watcher", "--exec", "login --password qzS3cretA4 && echo ok"}); got[2] != "login --password [REDACTED] && echo ok" {
		t.Errorf("--exec value = %q", got[2])
	}
}
