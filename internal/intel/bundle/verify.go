// Package bundle verifies Aguara's signed advisory-intel manifests
// in-process, so a future `aguara update` can trust a freshly fetched
// bundle without shelling out to the cosign binary.
//
// PR 1 scope: verification capability + measurement only. Nothing here
// is wired into `aguara update`, `--fresh`, or the on-disk cache yet;
// that lands in PR 2 / PR 3.
//
// The trust root is pinned in-binary: the manifest must be signed
// keyless by the intel-publish workflow on main
// (intel-publish.yml@refs/heads/main, issuer token.actions.githubusercontent.com),
// and the Sigstore trusted root is embedded so verification is offline.
package bundle

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/garagon/aguara/internal/intel"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// trustedRootJSON is the Sigstore public-good trusted root (Fulcio CA,
// Rekor + CT log keys, TSA roots). Embedded so verification needs no
// network. Refreshed deliberately when Sigstore rotates roots.
//
//go:embed trusted_root.json
var trustedRootJSON []byte

const (
	// ExpectedIssuer is the OIDC issuer of the keyless signing identity.
	ExpectedIssuer = "https://token.actions.githubusercontent.com"

	// ExpectedSANRegex pins the signer certificate's SAN to the
	// intel-publish workflow on main (the trust root for fresh intel).
	// Anchored at both ends so a lookalike path (a fork, a different
	// ref, a suffix) cannot match.
	ExpectedSANRegex = `^https://github\.com/garagon/aguara/\.github/workflows/intel-publish\.yml@refs/heads/main$`
)

// VerifyManifest verifies that manifestBytes is the artifact signed by
// the Sigstore bundle bundleBytes, under the pinned intel-publish
// identity. It returns nil only when the signature, certificate
// identity, and transparency-log / timestamp proofs all verify; any
// failure (bad signature, wrong identity, tampered artifact, malformed
// bundle) returns a non-nil error so callers fail closed.
func VerifyManifest(manifestBytes, bundleBytes []byte) error {
	certID, err := verify.NewShortCertificateIdentity(ExpectedIssuer, "", "", ExpectedSANRegex)
	if err != nil {
		return fmt.Errorf("bundle: build identity policy: %w", err)
	}
	return verifyWith(certID, manifestBytes, bundleBytes)
}

// verifyWith runs the verification against the embedded trusted root
// using the supplied certificate-identity policy. Split out so tests can
// assert that a non-matching identity is rejected without reaching into
// the verifier internals.
func verifyWith(certID verify.CertificateIdentity, manifestBytes, bundleBytes []byte) error {
	verifier, err := newVerifier()
	if err != nil {
		return err
	}
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(bundleBytes); err != nil {
		return fmt.Errorf("bundle: parse signing bundle: %w", err)
	}
	if _, err := verifier.Verify(&b, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(manifestBytes)),
		verify.WithCertificateIdentity(certID),
	)); err != nil {
		return fmt.Errorf("bundle: verification failed: %w", err)
	}
	return nil
}

// newVerifier builds a SignedEntityVerifier from the embedded trusted
// root, requiring an SCT, a transparency-log entry, and an observer
// timestamp (Rekor integrated time satisfies the last for keyless
// sign-blob bundles).
func newVerifier() (*verify.Verifier, error) {
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("bundle: load trusted root: %w", err)
	}
	v, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("bundle: build verifier: %w", err)
	}
	return v, nil
}

// VerifyAndParse verifies the manifest's signature under the pinned
// identity AND parses it, rejecting a manifest whose schema this build
// does not understand. It is the entry point a fresh-intel consumer
// (PR 2) will use: a verified-but-unreadable manifest must fail closed
// rather than be guessed at.
func VerifyAndParse(manifestBytes, bundleBytes []byte) (intel.SnapshotMeta, error) {
	if err := VerifyManifest(manifestBytes, bundleBytes); err != nil {
		return intel.SnapshotMeta{}, err
	}
	return parseManifest(manifestBytes)
}

// parseManifest decodes a manifest and rejects a future manifest_schema.
// The bundle_schema_version (the intel.Snapshot schema the blob decodes
// to) is checked downstream by the snapshot decoder; here we only gate
// on the manifest document's own schema.
func parseManifest(manifestBytes []byte) (intel.SnapshotMeta, error) {
	var m intel.SnapshotMeta
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return intel.SnapshotMeta{}, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	if m.ManifestSchema < 1 {
		return intel.SnapshotMeta{}, fmt.Errorf("bundle: manifest_schema missing or invalid (%d); a signed manifest must declare its schema", m.ManifestSchema)
	}
	if m.ManifestSchema > intel.ManifestSchema {
		return intel.SnapshotMeta{}, fmt.Errorf("bundle: manifest_schema %d is newer than this build supports (%d); upgrade aguara",
			m.ManifestSchema, intel.ManifestSchema)
	}
	return m, nil
}
