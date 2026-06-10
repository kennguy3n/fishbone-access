// Command migrate-lint validates the embedded SQL migrations for version
// integrity (well-formed filenames, unique and contiguous versions) and
// lock-safety (no operation that takes a heavy lock or is illegal under the
// per-migration transaction the runner uses). It is the engine behind
// `make migrate-check` and runs as part of the lint gate, mirroring the intent
// of visible-fishbone's `sng-migrate validate --strict`.
//
// It exits 0 when every migration passes and 1 (printing each violation) when
// any rule fails, so CI and the local lint gate fail loudly on an unsafe or
// mis-numbered migration before it can reach a database.
package main

import (
	"fmt"
	"os"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
)

func main() {
	result, err := migrations.Lint()
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-lint: cannot read migrations: %v\n", err)
		os.Exit(1)
	}
	if !result.OK() {
		fmt.Fprintln(os.Stderr, result.Err())
		os.Exit(1)
	}
	fmt.Println("migrate-lint: all migrations pass version-integrity and lock-safety checks")
}
