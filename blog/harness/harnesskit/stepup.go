package harnesskit

import (
	"encoding/base32"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPBase32Secret returns the deterministic base32 TOTP secret enrolled for a
// workspace owner. It is derived from the workspace slug so a re-run enrolls the
// SAME secret (idempotent) and any harness can regenerate currently-valid codes
// without persisting state. This is a demo authenticator seed, never a real
// user credential.
//
// The seed harness seals this secret into the owner's UserTOTPSecret row; the
// capture harness regenerates codes from it to satisfy the step-up gate on the
// evidence-pack export. Both derive it identically, so they always agree.
func TOTPBase32Secret(slug string) string {
	raw := []byte("fishbone-blog-totp::" + slug)
	for len(raw) < 20 { // RFC 4226 recommends ≥160-bit secrets
		raw = append(raw, '0')
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:20])
}

// StepUpDispenser yields fresh, server-acceptable 6-digit TOTP codes for the
// promote/export step-up gate. The server accepts codes within ±1 period of its
// clock and refuses any code a second time (anti-replay), so the dispenser
// hands out the current, next and previous step codes (three distinct,
// currently-valid codes) and, once those are spent, sleeps to the next period
// boundary to roll a fresh one. This drives the REAL replay-protected verifier
// rather than weakening it.
type StepUpDispenser struct {
	secret string
	used   map[string]bool
}

// NewStepUpDispenser builds a dispenser for a base32 TOTP secret (as returned by
// TOTPBase32Secret).
func NewStepUpDispenser(secret string) *StepUpDispenser {
	return &StepUpDispenser{secret: secret, used: map[string]bool{}}
}

func (d *StepUpDispenser) code(at time.Time) string {
	code, err := totp.GenerateCodeCustom(d.secret, at, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		Fatalf("generate TOTP code: %v", err)
	}
	return code
}

// Next returns an unused code the server will accept now, sleeping to the next
// 30s window if the three currently-valid codes are already spent.
func (d *StepUpDispenser) Next() string {
	for {
		now := time.Now()
		for _, off := range []time.Duration{0, 30 * time.Second, -30 * time.Second} {
			code := d.code(now.Add(off))
			if !d.used[code] {
				d.used[code] = true
				return code
			}
		}
		// All three valid codes spent this run — wait for the window to advance.
		sleep := 30*time.Second - time.Duration(now.Unix()%30)*time.Second + time.Second
		Logf("  step-up: waiting %s for a fresh TOTP window", sleep.Round(time.Second))
		time.Sleep(sleep)
	}
}
