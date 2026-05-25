package versions

import "testing"

func TestAffected(t *testing.T) {
	cases := []struct {
		name    string
		version string
		ranges  []Range
		want    bool
	}{
		// introduced:0, fixed:1.0.13 -> [0, 1.0.13)
		{"intro0 fixed: in range", "1.0.12", []Range{{Introduced: "0", Fixed: "1.0.13"}}, true},
		{"intro0 fixed: at fixed (exclusive)", "1.0.13", []Range{{Introduced: "0", Fixed: "1.0.13"}}, false},
		{"intro0 fixed: above fixed", "2.0.0", []Range{{Introduced: "0", Fixed: "1.0.13"}}, false},

		// introduced:1.0.0, fixed:1.0.13 -> [1.0.0, 1.0.13)
		{"bounded: below introduced", "0.9.9", []Range{{Introduced: "1.0.0", Fixed: "1.0.13"}}, false},
		{"bounded: at introduced (inclusive)", "1.0.0", []Range{{Introduced: "1.0.0", Fixed: "1.0.13"}}, true},
		{"bounded: in range", "1.0.12", []Range{{Introduced: "1.0.0", Fixed: "1.0.13"}}, true},
		{"bounded: at fixed (exclusive)", "1.0.13", []Range{{Introduced: "1.0.0", Fixed: "1.0.13"}}, false},

		// last_affected:1.0.12 (inclusive upper)
		{"last_affected: at bound (inclusive)", "1.0.12", []Range{{Introduced: "0", LastAffected: "1.0.12"}}, true},
		{"last_affected: above bound", "1.0.13", []Range{{Introduced: "0", LastAffected: "1.0.12"}}, false},

		// the TrapDoor shape: introduced:0, no upper bound -> matches everything
		{"whole-package: low version", "0.0.1", []Range{{Introduced: "0"}}, true},
		{"whole-package: high version", "99.99.99", []Range{{Introduced: "0"}}, true},
		{"whole-package: prerelease", "1.0.0-alpha", []Range{{Introduced: "0"}}, true},

		// empty introduced means no lower bound
		{"no lower bound: below fixed", "0.0.1", []Range{{Fixed: "1.0.0"}}, true},
		{"no lower bound: at fixed", "1.0.0", []Range{{Fixed: "1.0.0"}}, false},

		// prerelease vs bounds
		{"prerelease below release introduced", "1.0.0-rc.1", []Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, false},
		{"release at introduced", "1.0.0", []Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, true},

		// multiple ranges OR
		{"multi-range: matches second", "3.5.0", []Range{
			{Introduced: "1.0.0", Fixed: "1.1.0"},
			{Introduced: "3.0.0", Fixed: "4.0.0"},
		}, true},
		{"multi-range: matches none", "2.0.0", []Range{
			{Introduced: "1.0.0", Fixed: "1.1.0"},
			{Introduced: "3.0.0", Fixed: "4.0.0"},
		}, false},

		// malformed -> no match
		{"unparseable version", "not-a-version", []Range{{Introduced: "0"}}, false},
		// Overflowing component must not wrap into a value that mis-matches a bound.
		{"overflow version vs lower bound", "99999999999999999999.0.0", []Range{{Introduced: "1.0.0"}}, false},
		{"unparseable introduced bound", "1.0.0", []Range{{Introduced: "abc", Fixed: "2.0.0"}}, false},
		{"unparseable fixed bound", "1.0.0", []Range{{Introduced: "0", Fixed: "xyz"}}, false},
		{"empty range (no bounds)", "1.0.0", []Range{{}}, false},
		{"both fixed and last_affected", "1.0.0", []Range{{Introduced: "0", Fixed: "2.0.0", LastAffected: "1.5.0"}}, false},
		{"no ranges", "1.0.0", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Affected(tc.version, tc.ranges); got != tc.want {
				t.Errorf("Affected(%q, %+v) = %v, want %v", tc.version, tc.ranges, got, tc.want)
			}
		})
	}
}
