package fingerprint

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Scalar runs one query and returns its single integer result.
//
// A function rather than an interface returning *sql.Row, and that is a deliberate API choice.
// Go has no covariant returns, so an interface shaped around *sql.Row can only be satisfied by
// database/sql itself — every caller on a driver that is not database/sql, and every test, then
// needs a shim around a type it cannot construct. A function is satisfied by anything, so this
// module stays free of both a driver dependency and a mocking library. ScalarFromDB adapts
// *sql.DB, *sql.Tx and *sql.Conn.
type Scalar func(ctx context.Context, query string, args ...any) (int64, error)

// RowQuerier is what ScalarFromDB adapts: *sql.DB, *sql.Tx and *sql.Conn all satisfy it.
type RowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ScalarFromDB adapts a database/sql handle for use here.
func ScalarFromDB(db RowQuerier) Scalar {
	return func(ctx context.Context, query string, args ...any) (int64, error) {
		var n int64
		if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			return 0, err
		}

		return n, nil
	}
}

// ColumnRef is one side of a join.
type ColumnRef struct {
	Table  string
	Column string
}

func (c ColumnRef) String() string { return c.Table + "." + c.Column }

// DefaultMaxDistinctKeys bounds the work one measurement may do. Chosen to be large enough that a
// real dimension key fits and small enough that a scheduled control cannot become the most
// expensive query in the warehouse.
const DefaultMaxDistinctKeys = 5_000_000

var (
	// ErrUnmeasurable means the probe could not run: no permission, a missing table, a name the
	// catalog does not hold.
	//
	// It is an error and never a 0.0, and that is the single most important line in this file. A
	// zero returned for "we could not look" is indistinguishable from a join that genuinely
	// matches nothing, and the two have opposite meanings — one is inconclusive, the other is the
	// exact defect this module exists to catch.
	ErrUnmeasurable = errors.New("fingerprint: the join could not be measured")

	// ErrTooLarge means the left side has more distinct keys than the bound allows, so the
	// measurement was stopped rather than sampled.
	//
	// Sampling would be worse than refusing. A rate estimated over a sample moves between runs on
	// its own, and a comparator built on it would flip green/degraded from noise — then get
	// switched off, which is the failure mode the whole program is arranged around. An honest
	// "unverified" costs one inconclusive evaluation; a noisy rate costs the index its credibility.
	ErrTooLarge = errors.New("fingerprint: too many distinct keys to measure within the bound")

	// ErrBadIdentifier means a table or column name is not a plain identifier. Names reach the SQL
	// as text — no placeholder can carry an identifier — so anything unexpected is refused rather
	// than quoted and hoped for.
	ErrBadIdentifier = errors.New("fingerprint: not a plain SQL identifier")
)

// identifier is deliberately strict: letters, digits, underscore, dollar, and a leading letter or
// underscore. Real warehouse identifiers fit; anything needing more is refused loudly.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

func quote(name string) (string, error) {
	if !identifier.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrBadIdentifier, name)
	}

	return `"` + name + `"`, nil
}

// Options tunes a measurement.
type Options struct {
	// MaxDistinctKeys bounds the left side's distinct cardinality. Zero means
	// DefaultMaxDistinctKeys.
	MaxDistinctKeys int64
}

func (o Options) bound() int64 {
	if o.MaxDistinctKeys <= 0 {
		return DefaultMaxDistinctKeys
	}

	return o.MaxDistinctKeys
}

// MatchRate is the fraction of the LEFT side's distinct values present on the right, in [0,1].
//
// Ported from an earlier Python implementation where this measurement was first written and
// calibrated against real ERP schemas. Two details are carried over deliberately:
//
//   - DISTINCT on the left, not row count. A key repeated a million times on one side would
//     otherwise dominate the fraction and report a healthy join as broken, or the reverse.
//   - Compared AS TEXT. An int-versus-varchar key mismatch is common in real ERPs and would
//     otherwise mask a real overlap as a total miss — a false `broken`, which is the expensive
//     direction of wrong.
//
// # No thresholds, and no verdict
//
// This returns a number. It does not decide whether the number is acceptable, and it must not grow
// a threshold: the same rate means different things on an optional attribute and on a primary
// relationship, and only the caller knows which it has. Two tables with no overlapping keys return
// **0.0 and a nil error** — that is a successful measurement of an empty join, not a failure.
//
// Every genuine inability to measure is a typed error instead. See ErrUnmeasurable and ErrTooLarge.
func MatchRate(ctx context.Context, q Scalar, left, right ColumnRef, opts Options) (float64, error) {
	lt, err := quote(left.Table)
	if err != nil {
		return 0, err
	}
	lc, err := quote(left.Column)
	if err != nil {
		return 0, err
	}
	rt, err := quote(right.Table)
	if err != nil {
		return 0, err
	}
	rc, err := quote(right.Column)
	if err != nil {
		return 0, err
	}

	bound := opts.bound()

	// LIMIT bound+1 rather than LIMIT bound: reading one row past the cap is how the query
	// reports "there were more" instead of silently handing back a truncated count that looks
	// complete, rather than a truncated count that reads as the whole answer.
	total, err := q(ctx, fmt.Sprintf(
		`SELECT count(*) FROM (SELECT DISTINCT CAST(%s AS VARCHAR) AS k FROM %s LIMIT %d) t`,
		lc, lt, bound+1,
	))
	if err != nil {
		return 0, fmt.Errorf("%w: counting %s: %v", ErrUnmeasurable, left, err)
	}
	if total > bound {
		return 0, fmt.Errorf("%w: %s has more than %d distinct values", ErrTooLarge, left, bound)
	}
	if total == 0 {
		// An empty left side has nothing to match. Zero rather than an error, and zero rather than
		// one: there is no overlap to report, and calling it a full match would render an empty
		// table as a healthy join.
		return 0, nil
	}

	hit, err := q(ctx, fmt.Sprintf(
		`SELECT count(*) FROM (SELECT DISTINCT CAST(l.%s AS VARCHAR) AS k FROM %s l `+
			`WHERE CAST(l.%s AS VARCHAR) IN (SELECT CAST(%s AS VARCHAR) FROM %s) LIMIT %d) t`,
		lc, lt, lc, rc, rt, bound+1,
	))
	if err != nil {
		return 0, fmt.Errorf("%w: matching %s against %s: %v", ErrUnmeasurable, left, right, err)
	}

	return float64(hit) / float64(total), nil
}

// Probe measures a join and returns it filled in, with an unmeasurable one carrying a nil
// MatchRate and the reason — the shape a fingerprint stores.
//
// It never returns an error for a join it could not measure. That is the point: a failed probe has
// to travel INSIDE the fingerprint as an unverified join, because an error returned here would be
// handled by a caller who then has nothing to store, and "nothing to store" is how an unverified
// join becomes an absent join and then a green one.
func Probe(ctx context.Context, q Scalar, left, right ColumnRef, evidence Evidence, opts Options) Join {
	j := Join{Left: left.String(), Right: right.String(), Evidence: evidence}

	rate, err := MatchRate(ctx, q, left, right, opts)
	if err != nil {
		j.Unmeasured = err.Error()

		return j
	}
	j.MatchRate = &rate

	return j
}

// EvidenceFor reports whether a join follows a foreign key the schema itself declares.
//
// Separate from MatchRate on purpose, and this is a deviation from the plan's one-call signature
// worth naming: evidence is a SCHEMA fact and the rate is a MEASUREMENT. Folding them together
// would make every caller who wants a rate pay for a catalog query, and would give a catalog
// outage the power to reduce a measured rate to an unmeasured one. Probe takes the evidence as an
// argument for the same reason. Callers wanting both in one call compose them.
//
// An unreadable catalog yields Inferred, which is the safe direction: it makes a low rate read as
// "the model chose this key and it barely matches" rather than as a declared relationship that
// broke. Over-trusting a join is the expensive mistake.
func EvidenceFor(ctx context.Context, q Scalar, left, right ColumnRef) Evidence {
	const query = `
		SELECT count(*)
		FROM information_schema.referential_constraints rc
		JOIN information_schema.key_column_usage k
		  ON k.constraint_name = rc.constraint_name
		WHERE k.table_name = $1 AND k.column_name = $2`

	n, err := q(ctx, query, strings.ToLower(left.Table), strings.ToLower(left.Column))
	if err != nil {
		return Inferred
	}
	if n > 0 {
		return Declared
	}

	return Inferred
}
