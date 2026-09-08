package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ToLocal is the fingerprint as it stands: real table, column and join names.
//
// It never leaves the client's perimeter. Inside it, names are the whole value of the thing — a
// comparator diff that says `a.customer_id = b.cust_ref went from 97% to 0%` is an argument, and
// the same diff with hashes is an accusation nobody can check.
func (f RunFingerprint) ToLocal() RunFingerprint { return f.Canonical() }

// ToHashed is the same object with every identifier replaced by a salted HMAC.
//
// This is the form that may cross the perimeter: OEM telemetry, a cross-client benchmark, an
// attestation. Two runs of the same path still compare equal under one salt, so the comparison
// survives; nobody outside can recover a table name from it.
//
// HMAC-SHA256 rather than a bare hash of salt+name. A plain SHA-256 over a short, guessable string
// like `customers` is a dictionary attack with a few thousand entries, and prefixing a salt does
// not fix that once the salt leaks — HMAC is the construction built for keying, so it is the one
// used. Truncated to 128 bits, which is far past collision risk for a schema and keeps a payload
// readable.
//
// The salt is the caller's to manage and to keep. Rotating it makes every stored hashed
// fingerprint incomparable with every new one, which is a migration and not a config change.
//
// # What is deliberately NOT hashed
//
// Findings' Evidence maps travel unchanged, and an empty salt is refused, both for reasons the
// tests pin. A finding's evidence carries identifiers inside free-shaped values this package
// cannot walk safely — so rather than hash it badly, ToHashed drops it. A partial redaction that
// looks complete is worse than an obvious hole.
func (f RunFingerprint) ToHashed(salt []byte) RunFingerprint {
	if len(salt) == 0 {
		// An empty salt is not a salt. Returning an unhashed object here would hand a caller who
		// forgot to configure one a payload that looks redacted and is not, and it would leave the
		// perimeter. Returning the zero value loses data loudly instead.
		return RunFingerprint{}
	}

	h := func(s string) string { return hashIdentifier(salt, s) }

	out := RunFingerprint{
		TablesOffered:  mapEach(f.TablesOffered, h),
		TablesSelected: mapEach(f.TablesSelected, h),
		ColumnsUsed:    mapEach(f.ColumnsUsed, h),
		// Not a measurement of anything nameable — carried through as-is.
		RowCountMagnitude: f.RowCountMagnitude,
		OrgContextHash:    f.OrgContextHash,
	}

	if f.SourceVersions != nil {
		out.SourceVersions = make(map[string]string, len(f.SourceVersions))
		for k, v := range f.SourceVersions {
			// The KEY is a source name and gets hashed; the value is a version string and does not.
			out.SourceVersions[h(k)] = v
		}
	}

	for _, j := range f.Joins {
		out.Joins = append(out.Joins, Join{
			Left:  h(j.Left),
			Right: h(j.Right),
			// `On` is the predicate as written and is therefore full of identifiers. It is dropped
			// rather than hashed: it is free SQL text, and a regex that redacted most of it would
			// leave a payload that reads as safe.
			MatchRate: j.MatchRate,
			Evidence:  j.Evidence,
			// Unmeasured is an error string naming tables. Same reasoning; the fact that it was
			// unmeasured survives as the nil MatchRate, which is what a comparator reads.
		})
	}

	for _, fd := range f.InstructionFindings {
		// Kind is a fixed vocabulary ("dead_join", "collapsed_column") and is safe. Evidence is
		// dropped — see the doc comment.
		out.InstructionFindings = append(out.InstructionFindings, Finding{Kind: fd.Kind})
	}

	return out.Canonical()
}

// hashIdentifier hashes each dotted segment separately, so `orders.customer_id` stays two
// segments joined by a dot.
//
// Structure is preserved on purpose: a reader of a hashed fingerprint can still see that a join is
// column-to-column rather than table-to-table, and a comparator can still tell which side of a
// dotted reference changed. The names are gone; the shape is the thing being compared.
func hashIdentifier(salt []byte, name string) string {
	if name == "" {
		return ""
	}
	parts := strings.Split(name, ".")
	for i, p := range parts {
		mac := hmac.New(sha256.New, salt)
		mac.Write([]byte(p))
		parts[i] = hex.EncodeToString(mac.Sum(nil)[:16])
	}

	return strings.Join(parts, ".")
}

func mapEach(in []string, f func(string) string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}

	return out
}
