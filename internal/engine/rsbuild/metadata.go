package rsbuild

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entry for the rule this analyzer
// emits. Co-located with the analyzer so `aguara explain` and
// `list-rules` stay in sync. The ID is unchanged from the retired YAML
// rule; only the detection moved from co-presence to a real
// read->exfil binding.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleBuildWalletExfil,
			Name:     "Rust build.rs wallet/keystore exfiltration",
			Severity: "CRITICAL",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerRSBuild,
			Description: "A Cargo build script (build.rs) that reads crypto wallet or " +
				"keystore material (Sui / Move / Solana / Aptos keystores) and sends it " +
				"over the network. This is the TrapDoor-style crates.io payload: " +
				"build-time theft of signing keys. The analyzer binds the two halves: " +
				"the material reaching a network sink (reqwest / ureq / hyper / " +
				"TcpStream::connect / a Gist endpoint) must trace back, in one or two " +
				"simple let-binding hops, to a wallet/keystore read. A build.rs that " +
				"only compiles native code, reads a keystore without sending it, or hits " +
				"the network without touching a keystore does not trip it.",
			Remediation: "Build scripts must never read wallet or keystore material or " +
				"open network connections to send it. Remove the keystore read and the " +
				"network sink from build.rs. Audit the host and rotate any wallet keys, " +
				"mnemonics, or signing keys reachable from the build environment.",
		},
	}
}
