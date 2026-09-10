package pkgmeta

import "testing"

func TestURLUserinfoRedaction(t *testing.T) {
	for _, scheme := range []string{"git+https://", "git+custom://", "HTTPS://"} {
		in := scheme + "user:part@TOKEN@github.com/@scope/repo"
		want := scheme + "github.com/@scope/repo"
		if got := sanitizeGitURL(in); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
