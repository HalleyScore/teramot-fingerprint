package fingerprint_test

import (
	"encoding/json"
	"strings"
	"testing"

	fp "github.com/HalleyScore/teramot-fingerprint"
)

// Every identifier in the fixture, so the grep below cannot pass by only checking the obvious two.
var fixtureIdentifiers = []string{
	"orders", "customers", "legacy", "unused_table", "erp_source",
	"customer_id", "cust_ref", "order_total", "razon_social", "numero_siniestro",
}

func fixture() fp.RunFingerprint {
	return fp.RunFingerprint{
		TablesOffered:  []string{"orders", "customers", "legacy", "unused_table"},
		TablesSelected: []string{"orders", "customers"},
		Joins: []fp.Join{
			{Left: "orders.customer_id", Right: "customers.cust_ref",
				On: "o.customer_id = c.cust_ref", MatchRate: fp.RateOf(0.97), Evidence: fp.Declared},
			{Left: "orders.numero_siniestro", Right: "legacy.cust_ref",
				Evidence: fp.Inferred, Unmeasured: "permission denied for table legacy"},
		},
		ColumnsUsed:         []string{"orders.order_total", "customers.razon_social"},
		RowCountMagnitude:   fp.MagnitudeOf(1_126_156),
		InstructionFindings: []fp.Finding{{Kind: "dead_join", Evidence: map[string]any{"join": "orders.customer_id = customers.cust_ref"}}},
		SourceVersions:      map[string]string{"erp_source": "v3.1"},
		OrgContextHash:      "ctx-abc123",
	}
}

// The hashed JSON must contain no identifier from the fixture.
func TestHashedJSONLeaksNoIdentifier(t *testing.T) {
	blob, err := json.Marshal(fixture().ToHashed([]byte("a-real-salt")))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.ToLower(string(blob))

	for _, id := range fixtureIdentifiers {
		if strings.Contains(got, strings.ToLower(id)) {
			t.Errorf("hashed payload still contains %q:\n%s", id, blob)
		}
	}
}

// The same path under the same salt has to hash identically, or a comparator cannot use the hashed
// form at all — which is the only reason it exists.
func TestHashingIsStableUnderOneSalt(t *testing.T) {
	salt := []byte("s")
	a, _ := json.Marshal(fixture().ToHashed(salt))
	b, _ := json.Marshal(fixture().ToHashed(salt))

	if string(a) != string(b) {
		t.Error("two hashings of the same fingerprint differ; nothing could be compared")
	}

	c, _ := json.Marshal(fixture().ToHashed([]byte("different")))
	if string(a) == string(c) {
		t.Error("a different salt produced the same output, so the salt does nothing")
	}
}

// Structure survives: a dotted reference stays two segments, so a reader can still see that a join
// is column-to-column and a comparator can still tell which side changed.
func TestHashingPreservesTheDottedShape(t *testing.T) {
	h := fixture().ToHashed([]byte("s"))

	for _, j := range h.Joins {
		if strings.Count(j.Left, ".") != 1 || strings.Count(j.Right, ".") != 1 {
			t.Errorf("a dotted reference lost its shape: %q / %q", j.Left, j.Right)
		}
	}
}

// The measurements are the point of the payload and must come through untouched.
func TestHashingKeepsTheMeasurements(t *testing.T) {
	h := fixture().ToHashed([]byte("s"))

	if h.RowCountMagnitude == nil || *h.RowCountMagnitude != fp.Magnitude(1_126_156) {
		t.Errorf("magnitude did not survive: %v", h.RowCountMagnitude)
	}

	var measured, unmeasured int
	for _, j := range h.Joins {
		if j.Measured() {
			measured++
			if rate, _ := j.Rate(); rate != 0.97 {
				t.Errorf("rate changed to %v", rate)
			}
		} else {
			unmeasured++
		}
	}
	if measured != 1 || unmeasured != 1 {
		t.Errorf("measured/unmeasured = %d/%d, want 1/1 — the distinction must survive hashing", measured, unmeasured)
	}
	if len(h.InstructionFindings) != 1 || h.InstructionFindings[0].Kind != "dead_join" {
		t.Errorf("finding kinds did not survive: %+v", h.InstructionFindings)
	}
	if h.SourceVersions["erp_source"] != "" {
		t.Error("the source name was not hashed")
	}
	if len(h.SourceVersions) != 1 {
		t.Errorf("source versions lost: %+v", h.SourceVersions)
	}
}

// An empty salt is not a salt. Returning the object unhashed would hand a caller who forgot to
// configure one a payload that looks redacted, is not, and then leaves the perimeter.
func TestAnEmptySaltRefusesRatherThanPassingThrough(t *testing.T) {
	for _, salt := range [][]byte{nil, {}} {
		got := fixture().ToHashed(salt)

		blob, _ := json.Marshal(got)
		for _, id := range fixtureIdentifiers {
			if strings.Contains(strings.ToLower(string(blob)), strings.ToLower(id)) {
				t.Fatalf("an empty salt leaked %q — it must not pass the object through:\n%s", id, blob)
			}
		}
	}
}

// The fields that are DROPPED rather than hashed, asserted so a later change that starts emitting
// them has to come past a failing test. `On` is free SQL text and `Unmeasured` is an error string
// naming tables; a regex that redacted most of either would leave a payload reading as safe.
func TestFreeTextFieldsAreDroppedNotHashed(t *testing.T) {
	h := fixture().ToHashed([]byte("s"))

	for _, j := range h.Joins {
		if j.On != "" {
			t.Errorf("the join predicate survived hashing: %q", j.On)
		}
		if j.Unmeasured != "" {
			t.Errorf("the unmeasured reason survived hashing: %q", j.Unmeasured)
		}
	}
	for _, fd := range h.InstructionFindings {
		if len(fd.Evidence) != 0 {
			t.Errorf("finding evidence survived hashing: %+v", fd.Evidence)
		}
	}
}

// ToLocal keeps the names, because inside the perimeter the names ARE the value: "a.customer_id =
// b.cust_ref went from 97% to 0%" is an argument, and the same sentence in hashes is an accusation
// nobody can check.
func TestToLocalKeepsTheNames(t *testing.T) {
	l := fixture().ToLocal()

	if l.Joins[0].Left != "orders.customer_id" {
		t.Errorf("ToLocal altered a name: %q", l.Joins[0].Left)
	}
	if l.Joins[0].On == "" {
		t.Error("ToLocal dropped the predicate")
	}
}
