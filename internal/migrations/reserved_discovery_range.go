package migrations

// Feature E (account/asset auto-discovery + auto-onboarding) owns the exclusive
// migration range 0070–0079. This branch starts its migrations at 0070, so the
// numbers between the last migration merged to main (0062) and 0070 — i.e.
// 0063–0069 — are absent here. Those belong to sibling feature branches that
// have not merged yet, exactly the parallel-development situation
// reserved_parallel_ranges.go already documents.
//
// Declaring 63–69 reserved keeps the migrate-check contiguity rule (lint.go
// checkVersions) green on this branch: a present-and-reserved version is
// treated as present, so once a sibling's real migration lands on one of these
// numbers the check still passes and this reservation simply stops mattering.
//
// This runs after reservedVersions is initialised in lint.go (package-level var
// init precedes init funcs), so adding keys here is purely additive and
// idempotent with the other parallel-range declaration.
func init() {
	for v := 63; v <= 69; v++ {
		reservedVersions[v] = true
	}
}
