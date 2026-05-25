package versions

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		major int
		minor int
		patch int
		pre   int // number of prerelease identifiers
	}{
		{"1.2.3", true, 1, 2, 3, 0},
		{"v1.2.3", true, 1, 2, 3, 0}, // leading v accepted
		{"0.1.0", true, 0, 1, 0, 0},
		{"1.0.12", true, 1, 0, 12, 0},
		{"1.2.3-alpha.1", true, 1, 2, 3, 2}, // prerelease identifiers
		{"1.2.3+build.5", true, 1, 2, 3, 0}, // build metadata dropped
		{"1.2.3-rc.1+build", true, 1, 2, 3, 2},
		{"  1.2.3  ", true, 1, 2, 3, 0}, // trimmed
		// rejects
		{"", false, 0, 0, 0, 0},
		{"1.2", false, 0, 0, 0, 0},        // too few parts
		{"1.2.3.4", false, 0, 0, 0, 0},    // too many parts
		{"1.2.x", false, 0, 0, 0, 0},      // non-numeric
		{"-1.2.3", false, 0, 0, 0, 0},     // sign
		{"1.2.3-", false, 0, 0, 0, 0},     // empty prerelease
		{"1.2.3-a..b", false, 0, 0, 0, 0}, // empty prerelease identifier
		{"latest", false, 0, 0, 0, 0},
		// Overflowing numeric components must not silently wrap; reject
		// them as unparseable so range comparisons stay correct.
		{"9999999999999999999999999.0.0", false, 0, 0, 0, 0},
		{"1.18446744073709551616.0", false, 0, 0, 0, 0}, // 2^64 in minor
	}
	for _, tc := range cases {
		v, ok := Parse(tc.in)
		if ok != tc.ok {
			t.Errorf("Parse(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if v.major != tc.major || v.minor != tc.minor || v.patch != tc.patch {
			t.Errorf("Parse(%q) = %d.%d.%d, want %d.%d.%d", tc.in, v.major, v.minor, v.patch, tc.major, tc.minor, tc.patch)
		}
		if len(v.prerelease) != tc.pre {
			t.Errorf("Parse(%q) prerelease count = %d, want %d", tc.in, len(v.prerelease), tc.pre)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"1.2.0", "1.1.9", 1},
		{"1.0.12", "1.0.13", -1},
		{"1.0.13", "1.0.12", 1},
		// prerelease < release
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		// prerelease identifier ordering (semver §11 examples)
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},      // fewer fields < more
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1}, // numeric < alphanumeric
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1}, // numeric compared numerically, not lexically
		{"1.0.0-rc.1", "1.0.0-rc.1", 0},
		// build metadata is ignored for precedence
		{"1.0.0+build1", "1.0.0+build2", 0},
		{"1.0.0+build", "1.0.0", 0},
	}
	for _, tc := range cases {
		va, oka := Parse(tc.a)
		vb, okb := Parse(tc.b)
		if !oka || !okb {
			t.Fatalf("setup parse failed for %q/%q", tc.a, tc.b)
		}
		if got := va.Compare(vb); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Antisymmetry: Compare(b,a) must be the negation.
		if got := vb.Compare(va); got != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, got, -tc.want)
		}
	}
}
