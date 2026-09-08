package fingerprint_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fp "github.com/HalleyScore/teramot-fingerprint"
)

// A Scalar over scripted counts. No driver, no container, no mocking library: the arithmetic
// under test is "hit / total", and a function answering those two counts exercises it exactly.
// The SQL text itself is asserted separately (TestTheSQLComparesDistinctValuesAsText), so the fake
// not being a real engine cannot hide a wrong query.
type fakeDB struct {
	total, hit int64
	totalErr   error
	hitErr     error
	calls      []string
}

func (f *fakeDB) scalar() fp.Scalar {
	return func(_ context.Context, query string, _ ...any) (int64, error) {
		f.calls = append(f.calls, query)
		// The first count is the left side's distinct total; the second is the overlap.
		if len(f.calls) == 1 {
			return f.total, f.totalErr
		}

		return f.hit, f.hitErr
	}
}

func contains(hay, needle string) bool { return strings.Contains(hay, needle) }

var errProbe = errors.New("permission denied for table")

func ref(t, c string) fp.ColumnRef { return fp.ColumnRef{Table: t, Column: c} }

// The measurement contract, clause by clause.
func TestMatchRateAcceptance(t *testing.T) {
	ctx := context.Background()

	t.Run("no overlapping keys is 0.0 and a nil error", func(t *testing.T) {
		// The plan is explicit: 0.0, NOT an error. An empty join is a successful measurement of a
		// broken path, and turning it into an error would make the defect this module exists to
		// catch indistinguishable from a failure to look.
		rate, err := fp.MatchRate(ctx, (&fakeDB{total: 500, hit: 0}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})
		if err != nil {
			t.Fatalf("returned an error for an empty join: %v", err)
		}
		if rate != 0 {
			t.Errorf("rate = %v, want 0", rate)
		}
	})

	t.Run("partial overlap is the fraction", func(t *testing.T) {
		rate, err := fp.MatchRate(ctx, (&fakeDB{total: 1000, hit: 53}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		// 5.3% — the bind defect from the corpus.
		if rate != 0.053 {
			t.Errorf("rate = %v, want 0.053", rate)
		}
	})

	t.Run("no permission is a typed error, never 0.0", func(t *testing.T) {
		rate, err := fp.MatchRate(ctx, (&fakeDB{totalErr: errProbe}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})
		if !errors.Is(err, fp.ErrUnmeasurable) {
			t.Fatalf("err = %v, want ErrUnmeasurable", err)
		}
		if rate != 0 {
			t.Errorf("rate = %v; callers must read the error, and 0 here must never be mistaken for a measurement", rate)
		}
	})
}

// The two zeros are the whole point, so they get their own test: "measured, matched nothing"
// returns nil error, and "could not measure" returns a typed one. A caller distinguishing them
// only by the rate would conflate broken with inconclusive.
func TestTheTwoZerosAreDistinguishable(t *testing.T) {
	ctx := context.Background()

	_, emptyErr := fp.MatchRate(ctx, (&fakeDB{total: 10, hit: 0}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})
	_, blindErr := fp.MatchRate(ctx, (&fakeDB{totalErr: errProbe}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})

	if emptyErr != nil {
		t.Errorf("a measured-empty join errored: %v", emptyErr)
	}
	if blindErr == nil {
		t.Error("an unmeasurable join did not error, so it is indistinguishable from a measured zero")
	}
}

// A failure on the SECOND query must also be an error and not a zero. Easy to get wrong: the
// total succeeded, so a naive implementation has a denominator and returns 0/total.
func TestAFailureOnTheOverlapQueryIsAlsoAnError(t *testing.T) {
	_, err := fp.MatchRate(context.Background(),
		(&fakeDB{total: 1000, hitErr: errProbe}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})

	if !errors.Is(err, fp.ErrUnmeasurable) {
		t.Fatalf("err = %v, want ErrUnmeasurable — a half-completed probe is not a 0%% match", err)
	}
}

// Over the bound, the measurement stops rather than sampling. A sampled rate drifts between runs
// on its own, and a comparator flipping green/degraded from noise is the failure that gets the
// whole program switched off.
func TestTooManyKeysRefusesRatherThanSampling(t *testing.T) {
	db := &fakeDB{total: 101, hit: 50} // the bound+1 row came back
	_, err := fp.MatchRate(context.Background(), db.scalar(), ref("a", "x"), ref("b", "y"),
		fp.Options{MaxDistinctKeys: 100})

	if !errors.Is(err, fp.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if len(db.calls) != 1 {
		t.Errorf("ran %d queries; it must stop before the expensive overlap probe", len(db.calls))
	}
}

// Exactly at the bound is measurable. Off-by-one here would silently refuse legitimate joins.
func TestExactlyAtTheBoundIsStillMeasured(t *testing.T) {
	rate, err := fp.MatchRate(context.Background(),
		(&fakeDB{total: 100, hit: 100}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{MaxDistinctKeys: 100})
	if err != nil {
		t.Fatalf("refused a left side exactly at the bound: %v", err)
	}
	if rate != 1 {
		t.Errorf("rate = %v, want 1", rate)
	}
}

// An empty left side has nothing to match: 0, not 1, and not an error. Reporting a full match for
// an empty table would render a vanished source as a healthy join.
func TestAnEmptyLeftSideIsZeroNotOne(t *testing.T) {
	rate, err := fp.MatchRate(context.Background(),
		(&fakeDB{total: 0}).scalar(), ref("a", "x"), ref("b", "y"), fp.Options{})
	if err != nil {
		t.Fatalf("errored on an empty left side: %v", err)
	}
	if rate != 0 {
		t.Errorf("rate = %v, want 0", rate)
	}
}

// Two ported details, asserted on the SQL itself because the fake cannot show them: DISTINCT on
// the left (a key repeated a million times must not dominate) and comparison AS TEXT (an
// int/varchar mismatch must not mask a real overlap as a total miss).
func TestTheSQLComparesDistinctValuesAsText(t *testing.T) {
	db := &fakeDB{total: 10, hit: 5}
	if _, err := fp.MatchRate(context.Background(), db.scalar(), ref("orders", "ref"), ref("legacy", "code"), fp.Options{}); err != nil {
		t.Fatal(err)
	}

	for i, q := range db.calls {
		if !contains(q, "DISTINCT") {
			t.Errorf("query %d does not use DISTINCT: %s", i, q)
		}
		if !contains(q, "CAST") || !contains(q, "VARCHAR") {
			t.Errorf("query %d does not compare as text: %s", i, q)
		}
		if !contains(q, "LIMIT") {
			t.Errorf("query %d is unbounded: %s", i, q)
		}
	}
	if !contains(db.calls[0], `"orders"`) || !contains(db.calls[1], `"legacy"`) {
		t.Errorf("identifiers were not quoted: %v", db.calls)
	}
}

// Identifiers cannot be parameterized, so anything not a plain identifier is refused rather than
// interpolated. A rejected name must not come back as a 0.0 either.
func TestHostileIdentifiersAreRefused(t *testing.T) {
	for _, bad := range []string{
		`orders"; DROP TABLE users; --`,
		"orders; DELETE FROM x",
		"orders WHERE 1=1",
		"", "1orders", "or ders", "orders`", "or'ders",
	} {
		t.Run(bad, func(t *testing.T) {
			db := &fakeDB{total: 10, hit: 10}
			rate, err := fp.MatchRate(context.Background(), db.scalar(), ref(bad, "x"), ref("b", "y"), fp.Options{})
			if !errors.Is(err, fp.ErrBadIdentifier) {
				t.Fatalf("err = %v, want ErrBadIdentifier", err)
			}
			if rate != 0 || len(db.calls) != 0 {
				t.Errorf("it reached the database (calls=%d, rate=%v)", len(db.calls), rate)
			}
		})
	}
}

// Probe puts an unmeasurable join INSIDE the fingerprint rather than returning an error. An error
// leaves the caller with nothing to store, and nothing stored is how an unverified join becomes an
// absent one and then a green one.
func TestProbeCarriesFailureInsideTheJoin(t *testing.T) {
	j := fp.Probe(context.Background(), (&fakeDB{totalErr: errProbe}).scalar(),
		ref("a", "x"), ref("b", "y"), fp.Inferred, fp.Options{})

	if j.Measured() {
		t.Error("an unmeasurable probe produced a measured join")
	}
	if j.Unmeasured == "" {
		t.Error("the reason was lost, so a reader cannot tell why it is unverified")
	}
	if j.Left != "a.x" || j.Right != "b.y" || j.Evidence != fp.Inferred {
		t.Errorf("the join lost its identity: %+v", j)
	}

	ok := fp.Probe(context.Background(), (&fakeDB{total: 100, hit: 97}).scalar(),
		ref("a", "x"), ref("b", "y"), fp.Declared, fp.Options{})
	if rate, measured := ok.Rate(); !measured || rate != 0.97 {
		t.Errorf("a good probe gave (%v, %v), want (0.97, true)", rate, measured)
	}
}
