package bundle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The fixtures are a real new-format Sigstore bundle + manifest produced
// by the intel-publish workflow on main and downloaded from the
// intel-latest release. Verification runs fully offline against the
// embedded trusted root, so these tests need no network.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestVerifyManifestValid(t *testing.T) {
	m := readFixture(t, "valid_manifest.json")
	b := readFixture(t, "valid_bundle.sigstore.json")
	if err := VerifyManifest(m, b); err != nil {
		t.Fatalf("valid bundle must verify against the pinned identity, got: %v", err)
	}
}

func TestVerifyManifestInvalidSignature(t *testing.T) {
	m := readFixture(t, "valid_manifest.json")
	b := corruptSignature(t, readFixture(t, "valid_bundle.sigstore.json"))
	if err := VerifyManifest(m, b); err == nil {
		t.Fatal("expected verification to fail for a corrupted signature")
	}
}

func TestVerifyManifestWrongIdentity(t *testing.T) {
	m := readFixture(t, "valid_manifest.json")
	b := readFixture(t, "valid_bundle.sigstore.json")
	// Same issuer, a different workflow SAN: the real bundle's identity
	// (intel-publish.yml@refs/heads/main) must NOT satisfy this policy.
	wrong, err := verify.NewShortCertificateIdentity(ExpectedIssuer, "", "",
		`^https://github\.com/garagon/aguara/\.github/workflows/some-other-workflow\.yml@refs/heads/main$`)
	if err != nil {
		t.Fatalf("build wrong identity: %v", err)
	}
	if err := verifyWith(wrong, m, b); err == nil {
		t.Fatal("expected verification to fail when the signer identity does not match the policy")
	}
}

func TestVerifyManifestTamperedArtifact(t *testing.T) {
	m := readFixture(t, "valid_manifest.json")
	b := readFixture(t, "valid_bundle.sigstore.json")
	tampered := bytes.Replace(m, []byte(`"record_count"`), []byte(`"record_kount"`), 1)
	if bytes.Equal(tampered, m) {
		t.Fatal("fixture did not contain the field expected for tampering")
	}
	if err := VerifyManifest(tampered, b); err == nil {
		t.Fatal("expected verification to fail when the signed artifact is tampered")
	}
}

func TestParseManifestRejectsFutureSchema(t *testing.T) {
	m := readFixture(t, "valid_manifest.json")
	// A current-schema manifest parses cleanly.
	if _, err := parseManifest(m); err != nil {
		t.Fatalf("current-schema manifest must parse, got: %v", err)
	}
	// A manifest claiming a newer manifest_schema must be rejected.
	var obj map[string]any
	if err := json.Unmarshal(m, &obj); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	obj["manifest_schema"] = intel.ManifestSchema + 1
	future, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal future manifest: %v", err)
	}
	if _, err := parseManifest(future); err == nil {
		t.Fatal("expected parseManifest to reject a future manifest_schema")
	}
}

// VerifyAndParse must fail closed if the signature does not verify, even
// before reaching the schema check.
func TestVerifyAndParseFailsClosedOnBadSignature(t *testing.T) {
	m := readFixture(t, "valid_manifest.json")
	b := corruptSignature(t, readFixture(t, "valid_bundle.sigstore.json"))
	if _, err := VerifyAndParse(m, b); err == nil {
		t.Fatal("expected VerifyAndParse to fail closed on a bad signature")
	}
}

// corruptSignature flips a byte in the bundle's message signature so the
// cryptographic check must fail, while leaving the bundle structurally
// parseable.
func corruptSignature(t *testing.T, bundleJSON []byte) []byte {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(bundleJSON, &obj); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	ms, ok := obj["messageSignature"].(map[string]any)
	if !ok {
		t.Fatal("bundle missing messageSignature")
	}
	sig, ok := ms["signature"].(string)
	if !ok || len(sig) == 0 {
		t.Fatal("bundle missing signature")
	}
	b := []byte(sig)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	ms["signature"] = string(b)
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal corrupted bundle: %v", err)
	}
	return out
}
