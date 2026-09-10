package scriptrisk

import (
	"strings"
	"testing"
)

func TestPythonRemoteAssignmentState(t *testing.T) {
	for _, tc := range []struct {
		name, statements string
		want             bool
	}{
		{"decode self", "code = requests.get(url).content\ncode = code.decode()", true},
		{"read self", "code = requests.get(url)\ncode = code.read()", true},
		{"text self", "code = requests.get(url)\ncode = code.text", true},
		{"response identity self", "code = requests.get(url)\ncode = code\ncode = code.text", true},
		{"read then decode", "code = requests.get(url)\ncode = code.read()\ncode = code.decode()", true},
		{"two transforms", "code = requests.get(url).content\ncode = code.decode()\ncode = code.strip()", true},
		{"hop bound", "code = requests.get(url).content\ncode = code.decode()\ncode = code.strip()\ncode = code.strip()", false},
		{"local replacement", "code = requests.get(url).content\ncode = 'print(1)'", false},
		{"replacement after decode", "code = requests.get(url).content\ncode = code.decode()\ncode = 'print(1)'", false},
		{"response replacement", "code = requests.get(url)\ncode = SafeResponse()\ncode = code.text", false},
		{"replacement mentions variable", "code = requests.get(url).content\ncode = 'code.decode()'", false},
		{"response changes to payload", "code = requests.get(url)\ncode = code.content\ncode = 'safe'\ncode = code.text", false},
		{"fresh fetch resets depth", "code = requests.get(url).content\ncode = code.decode()\ncode = code.strip()\ncode = requests.get(other).text", true},
	} {
		for _, helper := range []bool{false, true} {
			mode := "inline"
			src := "import requests\n" + tc.statements + "\nexec(code)"
			if helper {
				mode = "helper"
				src = "import requests\ndef load():\n    " + strings.ReplaceAll(tc.statements, "\n", "\n    ") + "\n    return code\nexec(load())"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				if got := hasRule(t, "bootstrap.py", src, RulePythonRemoteExec); got != tc.want {
					t.Fatalf("remote fetch/exec = %v, want %v", got, tc.want)
				}
			})
		}
	}
}

func TestPythonRemoteSameLineAssignmentOrder(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"import requests\ncode = requests.get(url).text; exec(code)", true},
		{"import requests\ncode = requests.get(url).text\ncode = 'print(1)'; exec(code)", false},
		{"import requests\ncode = requests.get(url).content; code = code.decode(); exec(code)", true},
		{"import requests\ndef load():\n    code = requests.get(url).content; code = code.decode(); return code\nexec(load())", true},
		{"import requests\ndef load():\n    code = requests.get(url).content; code = 'safe'; return code\nexec(load())", false},
		{"import requests\ncode = requests.get(url).content\ncode = 'safe; exec(code)'; exec(code)", false},
	} {
		if got := hasRule(t, "bootstrap.py", tc.src, RulePythonRemoteExec); got != tc.want {
			t.Errorf("got %v, want %v for %s", got, tc.want, tc.src)
		}
	}
}

func TestPythonRemoteAssignmentSinkUsesPriorState(t *testing.T) {
	for _, src := range []string{
		"import requests\ncode = requests.get(url).text\ncode = code.strip()\ncode = code.strip()\ncode = eval(code)",
		"import requests\ncode = requests.get(url)\ncode = eval(code.text)",
		"import requests\nother = requests.get(url).text\ncode = other\nother = 'safe'\nexec(code)",
	} {
		if !hasRule(t, "bootstrap.py", src, RulePythonRemoteExec) {
			t.Error("lost remote provenance before RHS execution")
		}
	}
}
