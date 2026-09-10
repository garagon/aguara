package pkgmeta

import (
	"fmt"
	"strings"
	"testing"
)

func TestManifestExactScriptKeys(t *testing.T) {
	for _, alias := range []string{"Scripts", "SCRIPTS", `\u0053cripts`, `\u017fcripts`} {
		for _, value := range []string{"null", "false", "{}", `{"preinstall":"node --version"}`} {
			for _, src := range []string{
				fmt.Sprintf(`{"scripts":{"preinstall":"node index.js"},"%s":%s}`, alias, value),
				fmt.Sprintf(`{"%s":%s,"scripts":{"preinstall":"node index.js"}}`, alias, value),
			} {
				m, err := parseManifest([]byte(src))
				if err != nil || m.Scripts["preinstall"] != "node index.js" {
					t.Fatalf("canonical script lost for %s: %+v / %v", src, m, err)
				}
				if !hasRule(analyze(t, "package.json", src), RuleLocalJSLifecycle) {
					t.Fatalf("lifecycle finding missing for %s", src)
				}
			}
		}
	}
	for _, src := range []string{`{"Scripts":{"preinstall":"node index.js"}}`, `{"scripts":{"Preinstall":"node index.js"}}`} {
		if hasRule(analyze(t, "package.json", src), RuleLocalJSLifecycle) {
			t.Fatalf("noncanonical script became executable policy: %s", src)
		}
	}
	if !hasRule(analyze(t, "package.json", `{"\u0073cripts":{"preinstall":"node index.js"}}`), RuleLocalJSLifecycle) {
		t.Fatal("escaped exact key must be decoded")
	}
}

func TestManifestExactDependencyKeys(t *testing.T) {
	for _, key := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		for _, aliasValue := range []string{"null", "42", `{"x":"1.0.0"}`} {
			src := fmt.Sprintf(`{"%s":{"x":"git+https://github.com/example/project.git"},"%s":%s}`, key, strings.ToUpper(key), aliasValue)
			m, err := parseManifest([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]map[string]string{"dependencies": m.Dependencies, "devDependencies": m.DevDependencies, "optionalDependencies": m.OptionalDependencies, "peerDependencies": m.PeerDependencies}
			if got[key]["x"] != "git+https://github.com/example/project.git" {
				t.Fatalf("exact dependency overwritten: %s", src)
			}
			fs := analyze(t, "package.json", src)
			if !hasRule(fs, RuleGitInstallTrust) && !hasRule(fs, RuleOptionalGit) {
				t.Fatalf("git evidence missing: %s", src)
			}
		}
	}
}

func TestManifestExactPublishKeys(t *testing.T) {
	for _, src := range []string{
		`{"publishConfig":{"provenance":true},"PublishConfig":null}`,
		`{"publishConfig":{"provenance":true,"Provenance":false}}`,
		`{"publishConfig":{"provenance":true,"Provenance":null}}`,
		`{"publishConfig":{"provenance":true,"PROVENANCE":"wrong type"}}`,
	} {
		m, err := parseManifest([]byte(src))
		if err != nil || !manifestReferencesProvenance(m) {
			t.Fatalf("provenance lost: %s (%v)", src, err)
		}
	}
	for _, src := range []string{`{"PublishConfig":{"provenance":true}}`, `{"publishConfig":{"Provenance":true}}`} {
		m, err := parseManifest([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if manifestReferencesProvenance(m) {
			t.Fatalf("noncanonical provenance counted: %s", src)
		}
	}
}

func TestManifestExactKeyCompatibility(t *testing.T) {
	for _, src := range []string{`{}`, `null`, `{"scripts":null}`, `{"scripts":{},"Name":false,"Version":[],"extension":{"anything":true}}`} {
		if _, err := parseManifest([]byte(src)); err != nil {
			t.Fatalf("valid control %s: %v", src, err)
		}
	}
	for _, src := range []string{`[]`, `{"scripts":true}`, `{"dependencies":42}`, `{"name":[]}`, `{"scripts":`} {
		if _, err := parseManifest([]byte(src)); err == nil {
			t.Fatalf("invalid recognized field accepted: %s", src)
		}
	}
	m, err := parseManifest([]byte(`{"scripts":{"preinstall":"node index.js"},"scripts":{"test":"echo ok"}}`))
	if err != nil || len(m.Scripts) != 1 || m.Scripts["test"] != "echo ok" {
		t.Fatalf("duplicate exact key must use final object: %+v / %v", m, err)
	}
}

func TestManifestNestedDuplicateValues(t *testing.T) {
	for _, src := range []string{
		`{"scripts":{"preinstall":false,"preinstall":"node index.js"}}`,
		`{"scripts":{"preinstall":{},"preinstall":"node index.js"}}`,
	} {
		if !hasRule(analyze(t, "package.json", src), RuleLocalJSLifecycle) {
			t.Fatalf("final script lost: %s", src)
		}
	}
	src := `{"dependencies":{"x":false,"x":"git+https://github.com/example/project.git"}}`
	if !hasRule(analyze(t, "package.json", src), RuleGitInstallTrust) {
		t.Fatal("final dependency lost")
	}
	if hasRule(analyze(t, "package.json", `{"scripts":{"preinstall":"node index.js","preinstall":false}}`), RuleLocalJSLifecycle) {
		t.Fatal("invalid final value must remain rejected")
	}
}
