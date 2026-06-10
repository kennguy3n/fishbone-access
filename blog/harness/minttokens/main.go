// Command minttokens prints a long-lived owner JWT per blog workspace so the
// dev console (Login → "Bearer JWT (development)") can browse each tenant's
// seeded data for screenshots. Not part of the evidence pipeline — a local
// convenience that mints the same token shape the seed harness uses.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
)

func main() {
	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "AUTH_JWT_SECRET must be set")
		os.Exit(1)
	}
	for _, ws := range harnesskit.Workspaces {
		tok := harnesskit.MintJWT(secret, harnesskit.DefaultIssuer, harnesskit.DefaultAudience,
			ws.OwnerSub(), ws.TenantID, ws.OwnerRoles(), true, 12*time.Hour)
		fmt.Printf("%s\t%s\t%s\n", ws.Slug, ws.Region, tok)
	}
}
