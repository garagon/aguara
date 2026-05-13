package incident_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
)

// BenchmarkIncidentNPMCheck measures the per-call cost of CheckNPM on
// a small but realistic node_modules tree: one compromised package,
// two clean unscoped packages, one scoped package, and a fixture
// path that must be rejected.
func BenchmarkIncidentNPMCheck(b *testing.B) {
	dir := b.TempDir()
	nm := filepath.Join(dir, "node_modules")
	type pkg struct{ path, name, version string }
	pkgs := []pkg{
		{"event-stream", "event-stream", "3.3.6"},
		{"express", "express", "4.18.2"},
		{"react", "react", "18.3.1"},
		{"@scope/utils", "@scope/utils", "1.2.3"},
	}
	for _, p := range pkgs {
		d := filepath.Join(nm, filepath.FromSlash(p.path))
		if err := os.MkdirAll(d, 0o755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		body := []byte(`{"name":"` + p.name + `","version":"` + p.version + `"}`)
		if err := os.WriteFile(filepath.Join(d, "package.json"), body, 0o644); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	// Fixture path that the walk must skip.
	fix := filepath.Join(nm, "react", "examples", "demo")
	if err := os.MkdirAll(fix, 0o755); err != nil {
		b.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(fix, "package.json"),
		[]byte(`{"name":"ua-parser-js","version":"0.7.29"}`),
		0o644,
	); err != nil {
		b.Fatalf("write: %v", err)
	}

	opts := incident.CheckOptions{Path: nm}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := incident.CheckNPM(opts)
		if err != nil {
			b.Fatalf("CheckNPM: %v", err)
		}
	}
}
