package fingerprint_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	fp "github.com/HalleyScore/teramot-fingerprint"
)

// FP-1.2's acceptance: JSON round-trips without loss, and the optional fields distinguish "zero"
// from "absent".
func TestRoundTripIsLossless(t *testing.T) {
	in := fp.RunFingerprint{
		TablesOffered:  []string{"orders", "customers", "unused"},
		TablesSelected: []string{"orders", "customers"},
		Joins: []fp.Join{
			{Left: "orders.customer_id", Right: "customers.id", On: "o.customer_id = c.id",
				MatchRate: fp.RateOf(0.97), Evidence: fp.Declared},
			{Left: "orders.ref", Right: "legacy.code", Evidence: fp.Inferred,
				Unmeasured: "no permission"},
			{Left: "a.x", Right: "b.y", MatchRate: fp.RateOf(0), Evidence: fp.Inferred},
		},
		ColumnsUsed:         []string{"orders.total", "customers.name"},
		RowCountMagnitude:   fp.MagnitudeOf(1_234),
		InstructionFindings: []fp.Finding{{Kind: "dead_join", Evidence: map[string]any{"match_rate": 0.0}}},
		SourceVersions:      map[string]string{"erp": "v3"},
		OrgContextHash:      "abc123",
	}

	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out fp.RunFingerprint
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip lost data:\n in: %+v\nout: %+v", in, out)
	}
}

// The distinction the whole program rests on: an unmeasured join and a join measured at zero must
// survive serialization as different things. A float64 could not hold this difference, which is
// why MatchRate is a pointer.
func TestAbsentAndZeroSurviveSeparately(t *testing.T) {
	in := fp.RunFingerprint{Joins: []fp.Join{
		{Left: "a.x", Right: "b.y"},                          // never measured
		{Left: "c.x", Right: "d.y", MatchRate: fp.RateOf(0)}, // measured, matched nothing
	}}

	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out fp.RunFingerprint
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatal(err)
	}

	if out.Joins[0].Measured() {
		t.Error("an unmeasured join came back measured — inconclusive would be scored as broken")
	}
	if !out.Joins[1].Measured() {
		t.Error("a join measured at 0 came back unmeasured — broken would be scored as inconclusive")
	}
	if rate, ok := out.Joins[1].Rate(); !ok || rate != 0 {
		t.Errorf("measured-zero came back as (%v, %v)", rate, ok)
	}

	// And the wire form says so explicitly, rather than omitting the field: `omitempty` on a
	// pointer would render measured-zero and unmeasured identically as an absent key.
	if !strings.Contains(string(blob), `"match_rate":null`) {
		t.Errorf("unmeasured did not serialize as an explicit null: %s", blob)
	}
	if !strings.Contains(string(blob), `"match_rate":0`) {
		t.Errorf("measured-zero did not serialize as 0: %s", blob)
	}
}

// Rate() returns the ok flag rather than defaulting, because a caller that ignores it gets 0 for an
// unmeasured join — the exact confusion the type is arranged to prevent.
func TestRateDoesNotDefaultToZero(t *testing.T) {
	unmeasured := fp.Join{Left: "a.x", Right: "b.y"}
	if _, ok := unmeasured.Rate(); ok {
		t.Fatal("an unmeasured join reported a usable rate")
	}
}

func TestUnverifiedListsTheJoinsWithNoRate(t *testing.T) {
	f := fp.RunFingerprint{Joins: []fp.Join{
		{Left: "a.x", Right: "b.y", MatchRate: fp.RateOf(1)},
		{Left: "c.x", Right: "d.y"},
		{Left: "e.x", Right: "f.y", MatchRate: fp.RateOf(0)},
		{Left: "g.x", Right: "h.y", Unmeasured: "too large"},
	}}

	got := f.Unverified()
	if len(got) != 2 {
		t.Fatalf("got %d unverified, want 2 (the measured zero is NOT unverified)", len(got))
	}
	if got[0].Left != "c.x" || got[1].Left != "g.x" {
		t.Errorf("wrong joins: %+v", got)
	}
}

// FP-1.5's acceptance, verbatim from the plan.
func TestMagnitude(t *testing.T) {
	if a, b := fp.Magnitude(10_200_000_000), fp.Magnitude(9_900_000_000); a != b {
		t.Errorf("10.2e9 and 9.9e9 gave different magnitudes (%d vs %d); they must agree", a, b)
	}
	if a, b := fp.Magnitude(12), fp.Magnitude(1_200_000); a == b {
		t.Errorf("12 and 1.2M gave the same magnitude (%d); they must not", a)
	}

	for _, tc := range []struct {
		n    int64
		want int
	}{
		{0, 0}, {-5, 0}, {1, 0}, {9, 1}, {10, 1}, {100, 2}, {1_000_000, 6},
	} {
		if got := fp.Magnitude(tc.n); got != tc.want {
			t.Errorf("Magnitude(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

// The failure Magnitude exists for: an empty join makes an aggregate sum a cross product, and the
// answer arrives orders of magnitude too big. A 3% business change must not read the same way.
func TestMagnitudeIgnoresBusinessMovementAndCatchesTheCrossProduct(t *testing.T) {
	baseline := fp.Magnitude(1_126_156)

	if got := fp.Magnitude(1_160_000); got != baseline {
		t.Errorf("a 3%% rise changed the magnitude (%d vs %d) — that is a false positive", got, baseline)
	}
	if got := fp.Magnitude(10_170_214_761); got == baseline {
		t.Error("the cross-product figure shares the baseline's magnitude; nothing would fire")
	}
}

func TestValidateRejectsWhatWouldCompareWrongly(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    fp.RunFingerprint
	}{
		{"a join with no sides", fp.RunFingerprint{Joins: []fp.Join{{Left: "a.x"}}}},
		{"an evidence value outside the two", fp.RunFingerprint{
			Joins: []fp.Join{{Left: "a.x", Right: "b.y", Evidence: "guessed"}}}},
		{"a rate above 1", fp.RunFingerprint{
			Joins: []fp.Join{{Left: "a.x", Right: "b.y", MatchRate: fp.RateOf(1.5)}}}},
		{"a negative rate", fp.RunFingerprint{
			Joins: []fp.Join{{Left: "a.x", Right: "b.y", MatchRate: fp.RateOf(-0.1)}}}},
		{"a negative magnitude", fp.RunFingerprint{RowCountMagnitude: func() *int { n := -1; return &n }()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.f.Validate(); err == nil {
				t.Error("Validate accepted it")
			}
		})
	}

	ok := fp.RunFingerprint{Joins: []fp.Join{
		{Left: "a.x", Right: "b.y", MatchRate: fp.RateOf(0), Evidence: fp.Declared},
		{Left: "c.x", Right: "d.y"}, // unmeasured, no evidence — both legal
	}}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate rejected a legal fingerprint: %v", err)
	}
}

// Sets are order-insensitive; join ORDER is part of the path and must not be normalised away.
func TestCanonicalSortsSetsButNotJoins(t *testing.T) {
	f := fp.RunFingerprint{
		TablesOffered: []string{"c", "a", "b"},
		Joins:         []fp.Join{{Left: "z.x", Right: "y.w"}, {Left: "a.x", Right: "b.y"}},
	}

	got := f.Canonical()
	if !reflect.DeepEqual(got.TablesOffered, []string{"a", "b", "c"}) {
		t.Errorf("tables not sorted: %v", got.TablesOffered)
	}
	if got.Joins[0].Left != "z.x" {
		t.Error("joins were reordered; their order is part of the path")
	}
}
