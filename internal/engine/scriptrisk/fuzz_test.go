package scriptrisk

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

func FuzzAnalyze(f *testing.F) {
	f.Add("setup.py", "payload = base64.b64decode(blob)\nexec(payload)\n")
	f.Add("bootstrap.sh", "pip install git+http://packages.example/tool.git\n")
	f.Add("bootstrap.sh", "npm install http://packages.example/tool.tgz\n")
	f.Add("setup.py", "import requests\npayload = requests.get(url).text\nexec(payload)\n")
	f.Add("setup.py", `payload = "".join(chr(x) for x in [112, 114, 105, 110, 116])
exec(payload)
`)
	f.Add("setup.py", "def broken((((\n")
	a := New()
	f.Fuzz(func(t *testing.T, name, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{RelPath: name, Content: []byte(src)})
		if err != nil {
			return
		}
		for _, fd := range findings {
			if fd.RuleID == "" {
				t.Error("finding with empty RuleID")
			}
		}
	})
}
