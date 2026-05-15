package incident_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
)

func writeNPMPackage(t *testing.T, root, importPath, version string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(importPath))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	body := `{"name":` + jsonString(importPath) + `,"version":` + jsonString(version) + `}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
}

func jsonString(s string) string {
	// Minimal JSON string escaping for the few cases the test writes.
	return `"` + s + `"`
}

func TestIsCompromisedIn_NPMHit(t *testing.T) {
	cp := incident.IsCompromisedIn(incident.EcosystemNPM, "event-stream", "3.3.6")
	if cp == nil {
		t.Fatalf("expected event-stream 3.3.6 to be compromised, got nil")
	}
	if cp.Ecosystem != incident.EcosystemNPM {
		t.Errorf("expected ecosystem npm, got %q", cp.Ecosystem)
	}
}

func TestIsCompromisedIn_NPMMiss(t *testing.T) {
	// event-stream is in the npm list; checking pypi for the same name
	// must return nil, otherwise a Python package sharing a name with
	// an npm incident would falsely chain.
	if cp := incident.IsCompromisedIn(incident.EcosystemPyPI, "event-stream", "3.3.6"); cp != nil {
		t.Errorf("expected ecosystem filter to exclude pypi lookup, got: %+v", cp)
	}
}

func TestIsCompromised_LegacyTwoArg_ScopedToPyPI(t *testing.T) {
	// The legacy two-arg signature pre-dates the Ecosystem field
	// and is scoped to PyPI. A Python package whose metadata
	// name+version matches an npm advisory must not be falsely
	// flagged by the Python checker.
	if cp := incident.IsCompromised("event-stream", "3.3.6"); cp != nil {
		t.Errorf("legacy IsCompromised must not match npm event-stream from a Python lookup, got: %+v", cp)
	}
	// PyPI entries still match.
	if cp := incident.IsCompromised("litellm", "1.82.7"); cp == nil {
		t.Errorf("legacy IsCompromised should still find PyPI litellm 1.82.7")
	}
}

func TestCheckNPM_RequiresPath(t *testing.T) {
	if _, err := incident.CheckNPM(incident.CheckOptions{}); err == nil {
		t.Errorf("expected error when path is empty")
	}
}

func TestCheckNPM_DetectsCompromisedPackage(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "event-stream", "3.3.6")
	writeNPMPackage(t, nm, "express", "4.18.2")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 2 {
		t.Errorf("expected 2 packages read, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Severity != incident.SevCritical {
		t.Errorf("expected CRITICAL severity, got %q", result.Findings[0].Severity)
	}
}

func TestCheckNPM_ScopedPackages(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "@scope/legit", "1.0.0")
	writeNPMPackage(t, nm, "ua-parser-js", "0.7.29")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 2 {
		t.Errorf("expected 2 packages read, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 || result.Findings[0].Path == "" {
		t.Fatalf("expected one ua-parser-js finding with a path, got: %+v", result.Findings)
	}
}

func TestCheckNPM_NestedNodeModules(t *testing.T) {
	// A nested copy at node_modules/foo/node_modules/event-stream
	// must still be detected (npm legitimately ships nested deps
	// when a dep's version constraint cannot be hoisted).
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "foo", "1.0.0")
	writeNPMPackage(t, filepath.Join(nm, "foo", "node_modules"), "event-stream", "3.3.6")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for nested compromised dep, got %d: %+v", len(result.Findings), result.Findings)
	}
}

func TestCheckNPM_CleanTree(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "react", "18.3.1")
	writeNPMPackage(t, nm, "@scope/utils", "2.1.0")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("clean tree must produce no findings, got: %+v", result.Findings)
	}
}

func TestCheckNPM_CleanTreeJSONEmitsEmptyArrays(t *testing.T) {
	// JSON consumers expect a stable `findings: []` shape on a clean
	// tree. nil slices would marshal as `null`, breaking pipelines
	// that .length or .map() over the result.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "express", "4.18.2")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM error: %v", err)
	}
	out, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(out)
	if strings.Contains(js, `"findings":null`) || strings.Contains(js, `"credentials":null`) {
		t.Errorf("clean tree must emit empty arrays, got: %s", js)
	}
	if !strings.Contains(js, `"findings":[]`) {
		t.Errorf("expected findings:[] in JSON output, got: %s", js)
	}
}

func TestCheckNPM_NonExistentPath(t *testing.T) {
	if _, err := incident.CheckNPM(incident.CheckOptions{Path: "/nonexistent/path"}); err == nil {
		t.Errorf("expected error for nonexistent path")
	}
}

func TestCheckNPM_AcceptsProjectRoot(t *testing.T) {
	// `--path .` (project root with a sibling node_modules) is the
	// most user-friendly invocation. The checker normalizes it to
	// the node_modules child instead of silently reporting zero
	// packages.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "event-stream", "3.3.6")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: dir})
	if err != nil {
		t.Fatalf("CheckNPM should accept project root, got: %v", err)
	}
	if result.PackagesRead != 1 {
		t.Errorf("expected 1 package, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 {
		t.Errorf("project-root scan should still detect compromised dep, got: %+v", result.Findings)
	}
}

func TestCheckNPM_DetectsNodeIPC2026Compromise(t *testing.T) {
	// The May 2026 node-ipc compromise (Socket / StepSecurity):
	// versions 9.1.6, 9.2.3, and 12.0.1 published an obfuscated
	// CommonJS payload. Each must surface as CRITICAL with the
	// SOCKET-2026-05-14 advisory.
	for _, ver := range []string{"9.1.6", "9.2.3", "12.0.1"} {
		ver := ver
		t.Run(ver, func(t *testing.T) {
			dir := t.TempDir()
			nm := filepath.Join(dir, "node_modules")
			writeNPMPackage(t, nm, "node-ipc", ver)

			result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
			if err != nil {
				t.Fatalf("CheckNPM error: %v", err)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("expected 1 finding for node-ipc %s, got %d: %+v", ver, len(result.Findings), result.Findings)
			}
			f := result.Findings[0]
			if f.Severity != incident.SevCritical {
				t.Errorf("expected CRITICAL, got %q", f.Severity)
			}
			if !strings.Contains(f.Title+f.Detail, "SOCKET-2026-05-14-node-ipc") {
				t.Errorf("expected SOCKET-2026-05-14-node-ipc advisory reference, got title=%q detail=%q", f.Title, f.Detail)
			}
		})
	}
}

func TestCheckNPM_DetectsHistoricalNodeIPCCompromises(t *testing.T) {
	// The 2022 "peacenotwar" / RIAEvangelist incident. These
	// versions are listed as historical malicious to surface them
	// on installs that still pin or transitively depend on them.
	for _, ver := range []string{"10.1.1", "10.1.2", "11.0.0", "11.1.0"} {
		ver := ver
		t.Run(ver, func(t *testing.T) {
			dir := t.TempDir()
			nm := filepath.Join(dir, "node_modules")
			writeNPMPackage(t, nm, "node-ipc", ver)

			result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
			if err != nil {
				t.Fatalf("CheckNPM error: %v", err)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("expected 1 finding for historical node-ipc %s, got %d", ver, len(result.Findings))
			}
			if !strings.Contains(result.Findings[0].Title+result.Findings[0].Detail, "SOCKET-node-ipc-historical-malicious") {
				t.Errorf("expected historical advisory reference, got: %+v", result.Findings[0])
			}
		})
	}
}

func TestCheckNPM_NodeIPCCleanVersions(t *testing.T) {
	// Versions adjacent to the compromised tuples must not be
	// flagged. 12.0.0 is the immediately prior version to the
	// compromised 12.0.1 in the same minor series.
	for _, ver := range []string{"9.0.0", "9.1.5", "12.0.0", "9.2.4"} {
		ver := ver
		t.Run(ver, func(t *testing.T) {
			dir := t.TempDir()
			nm := filepath.Join(dir, "node_modules")
			writeNPMPackage(t, nm, "node-ipc", ver)

			result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
			if err != nil {
				t.Fatalf("CheckNPM error: %v", err)
			}
			if len(result.Findings) != 0 {
				t.Errorf("clean node-ipc %s must not produce findings, got: %+v", ver, result.Findings)
			}
		})
	}
}

func TestCheckNPM_RejectsBareDirWithoutNodeModules(t *testing.T) {
	// A directory that is neither node_modules nor a project with
	// one must error rather than report a clean (and misleading)
	// zero-finding result.
	dir := t.TempDir()
	if _, err := incident.CheckNPM(incident.CheckOptions{Path: dir}); err == nil {
		t.Errorf("expected error on directory without node_modules child")
	}
}

func TestCheckNPM_PnpmStoreLayout(t *testing.T) {
	// pnpm exposes top-level packages as symlinks into a virtual
	// store under node_modules/.pnpm. The real manifests live at
	// node_modules/.pnpm/<spec>/node_modules/<name>/package.json
	// and must be parsed as installed dependencies.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, filepath.Join(nm, ".pnpm", "event-stream@3.3.6", "node_modules"), "event-stream", "3.3.6")
	// A scoped variant.
	writeNPMPackage(t, filepath.Join(nm, ".pnpm", "@scope+name@1.0.0", "node_modules"), "@scope/name", "1.0.0")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 2 {
		t.Errorf("expected 2 packages in pnpm store, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 || result.Findings[0].Title == "" {
		t.Fatalf("expected one event-stream finding, got: %+v", result.Findings)
	}
}

func TestCheckNPM_IgnoresFixtureNodeModules(t *testing.T) {
	// A build-tool style fixture: an installed package ships a
	// test fixture that itself has a node_modules tree
	// (node_modules/build-tool/examples/some-app/node_modules/x/package.json).
	// The state-machine path check must reject the nested node_modules
	// because of the `examples/some-app` intermediate segments.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "build-tool", "1.0.0")
	deep := filepath.Join(nm, "build-tool", "examples", "some-app", "node_modules")
	if err := os.MkdirAll(filepath.Join(deep, "event-stream"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(deep, "event-stream", "package.json"),
		[]byte(`{"name":"event-stream","version":"3.3.6"}`),
		0o644,
	); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 1 {
		t.Errorf("expected only 1 installed package (build-tool), got %d", result.PackagesRead)
	}
	if len(result.Findings) != 0 {
		t.Errorf("fixture node_modules must not chain, got: %+v", result.Findings)
	}
}

func TestCheckNPM_IgnoresFixtureManifests(t *testing.T) {
	// A package may ship its own examples / test fixtures that contain
	// a `package.json` (e.g. fixture for a transpiler). Those are not
	// installed dependencies and must not be parsed as such.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "real-pkg", "1.0.0")
	// A fixture manifest with a known-compromised tuple deep inside
	// real-pkg/examples/.
	fixDir := filepath.Join(nm, "real-pkg", "examples", "scenario")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(fixDir, "package.json"),
		[]byte(`{"name":"event-stream","version":"3.3.6"}`),
		0o644,
	); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 1 {
		t.Errorf("expected only 1 installed package, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 0 {
		t.Errorf("fixture manifests must not produce findings, got: %+v", result.Findings)
	}
}
