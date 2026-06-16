package migrations

// This file declares the migration version numbers between the last migration
// that has merged to main (0026) and this feature's assigned range (0060–0069)
// as RESERVED for the migrate-check contiguity rule (see reservedVersions and
// checkVersions in lint.go).
//
// Why this is needed: this repository is being built by several parallel
// feature branches, each assigned its own exclusive 10-wide migration range so
// filenames never collide (this feature owns 0060–0069). Until the sibling
// branches that own 0027–0059 merge, those versions are absent on THIS branch,
// which the contiguity check would otherwise flag as an undeclared gap and fail
// `make lint` / `make migrate-check`. Declaring them reserved is exactly the
// mechanism lint.go documents for an intentional, by-design gap.
//
// This is forward-compatible with the sibling merges: lint.go states that a
// "present-and-reserved version is harmless because the contiguity check treats
// it as present", so once a sibling's real migration lands on one of these
// numbers the check still passes — the reservation simply stops mattering.
//
// reservedVersions is a package-level map initialised in lint.go; this init runs
// after that initialisation, so adding keys here is safe and additive (it never
// removes an existing reservation). Declaring the same number from more than one
// parallel branch is idempotent.
func init() {
	for v := 27; v <= 59; v++ {
		reservedVersions[v] = true
	}
}
