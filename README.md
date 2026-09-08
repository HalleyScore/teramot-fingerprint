# teramot-fingerprint

**The shared record of how a query run reached its answer.**

A fingerprint is the *path*, not the answer: which tables were offered and selected, which joins
were used and what fraction of rows each actually matched, which columns were read, what the
instruction checker found, and the order of magnitude of the row count. Never a value a business
would recognise.

```go
import fp "github.com/HalleyScore/teramot-fingerprint"

rate, err := fp.MatchRate(ctx, fp.ScalarFromDB(db),
    fp.ColumnRef{Table: "orders", Column: "customer_id"},
    fp.ColumnRef{Table: "customers", Column: "id"},
    fp.Options{})
```

## Three consumers, which is why this is a module

| consumer | role |
|---|---|
| the **query engine** | **computes** a fingerprint at run time — the only component holding the SQL and the live connection |
| the **monitor** | **parses** one and compares it against a frozen baseline, to produce an index |
| a third service | reads the joins |

The engine's own internal shared package cannot serve this: it is wired with a local `replace`, so
it is consumable only from inside that monorepo. Three separate implementations of one measurement
would drift, and then the index stops being comparable between services — which is the entire point
of having an index.

This module has **no dependencies** outside the standard library, deliberately: it sits in the
import graph of three services, and anything it pulls in, they all pull in.

For the same reason its `go` directive names the **lowest** version it actually needs, not the
newest available. A leaf library that over-declares drags every consumer's toolchain forward on
`go get` — the first fetch into `teramot-aleph` bumped that module from 1.25.3 to 1.26.7 before
this was corrected.

## The two rules everything here follows

**1. Absent is not zero.** Every optional measurement is a pointer.

```go
j.MatchRate == nil    // never measured  → inconclusive
*j.MatchRate == 0     // measured, matched nothing → broken
```

A control that *could not be checked* and a control that *failed* are opposite facts, and a
`float64` cannot hold the difference. `Join.Rate()` returns `(value, ok)` rather than defaulting,
because a caller who ignores the flag gets `0` for an unmeasured join — the one mistake this type
is arranged to prevent. The JSON keeps it too: unmeasured serializes as an explicit `null`, not an
omitted key.

**2. Measurement, never verdict.** `MatchRate` returns a number and no opinion, and must never grow
a threshold. The same rate means different things on an optional attribute and on a primary
relationship, and only the caller knows which it has.

Two tables with no overlapping keys return **`0.0` and a nil error** — a successful measurement of
an empty join. Every genuine inability to measure is a typed error instead:

| | |
|---|---|
| `ErrUnmeasurable` | no permission, missing table, a name the catalog does not hold |
| `ErrTooLarge` | more distinct keys than the bound allows — stopped, **not sampled** |
| `ErrBadIdentifier` | not a plain SQL identifier, refused before reaching the database |

`ErrTooLarge` exists because sampling would be worse than refusing: an estimated rate moves between
runs on its own, and a comparator flipping green/degraded from noise gets switched off. One honest
`inconclusive` costs an evaluation; a noisy rate costs the index its credibility.

## What `MatchRate` measures, and why that way

The fraction of the **left side's distinct values** present on the right, compared **as text**.

Both details are ported from an earlier Python implementation, where this measurement was first
written and calibrated against real ERP schemas:

- **DISTINCT, not row count** — a key repeated a million times on one side would otherwise dominate
  the fraction and report a healthy join as broken, or the reverse.
- **Compared as text** — an int-versus-varchar key mismatch is common in real ERPs and would
  otherwise mask a real overlap as a total miss. A false `broken` is the expensive direction.

The anti-threshold argument travels with it: *a legitimate join can match a small fraction (an
optional attribute, a filtering lookup) while a broken one matches a plausible-looking chunk.* The
pair — "the model inferred this key" plus "it matched 5% of the rows" — is what decides it for a
human, in any schema, without calibration. Hence `Evidence`.

## Two serializations

`ToLocal()` keeps real names and never leaves the client's perimeter — inside it, the names *are*
the value: *"`a.customer_id = b.cust_ref` went from 97% to 0%"* is an argument, and the same
sentence in hashes is an accusation nobody can check.

`ToHashed(salt)` replaces every identifier with a salted HMAC-SHA256, truncated to 128 bits. Same
path under the same salt still compares equal, so a cross-perimeter comparison survives. Dotted
structure is preserved (`table.column` stays two segments) because the shape is what is being
compared.

HMAC rather than a bare hash of `salt+name`: a plain SHA-256 over a short, guessable string like
`customers` is a dictionary attack with a few thousand entries.

Free-text fields — the join predicate, the unmeasured reason, a finding's evidence map — are
**dropped, not hashed**. They are full of identifiers in shapes this package cannot walk safely, and
a partial redaction that looks complete is worse than an obvious hole. An empty salt returns the
zero value rather than passing the object through unhashed.

## Development

```sh
make check   # gofmt + vet + go test -race
```

## Status

Complete and tagged: the type, `MatchRate`, both serializations and the magnitude helper, each with
the acceptance tests its specification called for. Pre-1.0 — the type is expected to gain fields as
its consumers find what a comparator actually needs, and adding a field is additive for anything
reading the JSON.
