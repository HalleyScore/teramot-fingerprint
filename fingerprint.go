// Package fingerprint is the shared record of HOW a query run reached its answer.
//
// It is a module rather than a package inside any one service because three separate services
// need the same type and cannot share one any other way:
//
//   - the QUERY ENGINE computes a fingerprint at run time. It is the only component holding the
//     SQL and the live connection.
//   - the MONITOR parses one and compares it against a frozen baseline.
//   - a third consumer reads the joins.
//
// The engine's own internal shared package cannot serve it: that directory is wired with a local
// `replace`, so it is consumable only from inside that monorepo. Three separate implementations of
// one measurement would drift, and the index built on them would stop being comparable between
// services — which is the entire point of having an index.
//
// # The rule this type exists to enforce
//
// A fingerprint records the PATH, never the answer. No field here holds a value a business would
// recognise, with one deliberate exception: RowCountMagnitude, which is an order of magnitude and
// never the number. Comparing values lights up on ordinary business movement and gets switched off
// in its second week; comparing the path catches the failure nobody sees — the answer that still
// renders while the join under it matches nothing.
//
// # Absent is not zero
//
// Every optional measurement is a pointer, and that is load-bearing rather than idiomatic taste.
// A join with MatchRate == nil was never measured; a join with *MatchRate == 0 was measured and
// matched nothing. The first is `inconclusive` and the second is `broken` — a control that could
// not be checked versus a control that failed. Collapsing them into a float64 publishes the worst
// possible reading of something nobody looked at.
package fingerprint

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
)

// Evidence says where a join's keys came from, which is what makes a low match rate readable.
//
// The pair is what decides it for a human: "the model inferred this key" plus "it matched 5% of
// the rows" is decisive in any schema and needs no calibration. Either half alone is not — a
// legitimate join can match a small fraction (an optional attribute, a filtering lookup) while a
// broken one matches a plausible-looking chunk.
type Evidence string

const (
	// Declared — the join follows a relationship the schema itself states (a foreign key).
	Declared Evidence = "declared"
	// Inferred — the join was chosen by the model, on names and shapes.
	Inferred Evidence = "inferred"
)

func (e Evidence) Valid() bool { return e == Declared || e == Inferred }

// Join is one join in the path, and its measurement.
type Join struct {
	// Left and Right are `table.column`.
	Left  string `json:"left"`
	Right string `json:"right"`
	// On is the join predicate as written, kept verbatim so a human can read the path back.
	On string `json:"on,omitempty"`
	// MatchRate is the fraction of the LEFT side's distinct values present on the right, in [0,1].
	//
	// nil means NOT MEASURED and must stay distinguishable from measured-zero forever: an
	// unverified join is inconclusive, a join measured at 0 is broken. See the package comment.
	MatchRate *float64 `json:"match_rate"`
	// Evidence is empty when unknown, which is again not the same as Inferred.
	Evidence Evidence `json:"evidence,omitempty"`
	// Unmeasured says why MatchRate is nil, when something is known. Never a substitute for the
	// nil itself: a reader that only checks this string would treat an unexplained gap as fine.
	Unmeasured string `json:"unmeasured,omitempty"`
}

// Measured reports whether this join carries a rate at all.
func (j Join) Measured() bool { return j.MatchRate != nil }

// Rate is the measured fraction, and false when the join was never measured. Callers that ignore
// the second return get 0 for an unmeasured join, which is the one mistake this whole type is
// arranged to prevent — so it is returned, not defaulted.
func (j Join) Rate() (float64, bool) {
	if j.MatchRate == nil {
		return 0, false
	}

	return *j.MatchRate, true
}

// Finding is one thing the instruction checker said about this run.
type Finding struct {
	// Kind is the finding's class, e.g. "dead_join" or "collapsed_column".
	Kind string `json:"kind"`
	// Evidence carries the finding's own detail. Free-shaped on purpose: the checker that produces
	// findings evolves faster than this contract, and a new finding kind must not require a
	// version bump on all three consumers.
	Evidence map[string]any `json:"evidence,omitempty"`
}

// RunFingerprint is the whole path of one run.
type RunFingerprint struct {
	// TablesOffered is what the run could see; TablesSelected is what it used. Both matter: a
	// table vanishing from Offered is a schema change, while one vanishing from Selected with the
	// same Offered set is the model choosing differently.
	TablesOffered  []string `json:"tables_offered,omitempty"`
	TablesSelected []string `json:"tables_selected,omitempty"`
	Joins          []Join   `json:"joins,omitempty"`
	ColumnsUsed    []string `json:"columns_used,omitempty"`
	// RowCountMagnitude is log10 of the row count, rounded — never the count. nil means not
	// measured, which is not magnitude zero (a single-row answer).
	RowCountMagnitude   *int              `json:"row_count_magnitude"`
	InstructionFindings []Finding         `json:"instruction_findings,omitempty"`
	SourceVersions      map[string]string `json:"source_versions,omitempty"`
	// OrgContextHash pins the org context the run was answered under. A path that changed because
	// the written instructions changed is a different fact from one that changed because the data
	// did, and without this the two are indistinguishable.
	OrgContextHash string `json:"org_context_hash,omitempty"`
}

// ErrInvalidEvidence is returned by Validate for an evidence value outside the two allowed.
var ErrInvalidEvidence = errors.New("fingerprint: evidence must be declared or inferred")

// Validate rejects a fingerprint that would compare wrongly rather than loudly.
func (f RunFingerprint) Validate() error {
	for i, j := range f.Joins {
		if j.Left == "" || j.Right == "" {
			return fmt.Errorf("fingerprint: join %d has no left or right side", i)
		}
		if j.Evidence != "" && !j.Evidence.Valid() {
			return fmt.Errorf("%w: join %d has %q", ErrInvalidEvidence, i, j.Evidence)
		}
		if rate, ok := j.Rate(); ok && (rate < 0 || rate > 1) {
			return fmt.Errorf("fingerprint: join %d has a match rate of %v, outside [0,1]", i, rate)
		}
	}
	if f.RowCountMagnitude != nil && *f.RowCountMagnitude < 0 {
		return fmt.Errorf("fingerprint: row count magnitude %d is negative", *f.RowCountMagnitude)
	}

	return nil
}

// Unverified lists the joins carrying no rate. One entry is enough to make an evaluation
// inconclusive: a path that is half unmeasured has not been checked, and scoring the measured half
// as green reports health nobody observed.
func (f RunFingerprint) Unverified() []Join {
	var out []Join
	for _, j := range f.Joins {
		if !j.Measured() {
			out = append(out, j)
		}
	}

	return out
}

// Magnitude is log10 of n, rounded, and never n.
//
// It exists for one failure: the answer that came back as "US$ 10.2 billion" because a join went
// empty and an aggregate summed a cross product. Two counts an order of magnitude apart is a
// signal; two counts 3% apart is a business that grew, and reporting that as a change is how a
// comparator earns the reputation that gets it switched off.
//
// Zero and negative counts return 0. A row count cannot be negative, and log10(0) is undefined —
// callers distinguish "no rows" from "not measured" with the pointer, not with a sentinel here.
func Magnitude(n int64) int {
	if n <= 0 {
		return 0
	}

	return int(math.Round(math.Log10(float64(n))))
}

// MagnitudeOf is Magnitude as a pointer, for assigning to RowCountMagnitude.
func MagnitudeOf(n int64) *int {
	m := Magnitude(n)

	return &m
}

// RateOf wraps a measured rate for assigning to Join.MatchRate. There is deliberately no helper
// that turns an error into a zero.
func RateOf(rate float64) *float64 { return &rate }

// Canonical returns a copy with every set sorted, so two fingerprints of the same path compare
// equal regardless of the order the producer happened to emit them in.
//
// Joins are NOT sorted: their order is part of the path, and a query that joins A then B is a
// different shape from one that joins B then A even when the set matches.
func (f RunFingerprint) Canonical() RunFingerprint {
	out := f
	out.TablesOffered = sortedCopy(f.TablesOffered)
	out.TablesSelected = sortedCopy(f.TablesSelected)
	out.ColumnsUsed = sortedCopy(f.ColumnsUsed)

	return out
}

func sortedCopy(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)

	return out
}

// MarshalJSON is the wire form. Declared explicitly so the round-trip is a tested contract rather
// than whatever the struct tags happen to produce after the next edit.
func (f RunFingerprint) MarshalJSON() ([]byte, error) {
	type wire RunFingerprint

	return json.Marshal(wire(f))
}
