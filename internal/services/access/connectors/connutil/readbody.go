// Package connutil holds small HTTP helpers shared by the access connectors.
package connutil

import (
	"fmt"
	"io"
)

// MaxResponseBytes bounds a single connector HTTP response body. Connector
// pages are capped at a few hundred items, so even a verbose page stays well
// under this ceiling; it exists purely so that one misbehaving, hostile, or
// compromised upstream cannot exhaust the memory of the shared multi-tenant
// host by streaming an unbounded body into io.ReadAll.
const MaxResponseBytes = 32 << 20 // 32 MiB

// ReadBody reads an entire response body, failing closed if it exceeds
// MaxResponseBytes. See ReadBodyLimit.
func ReadBody(r io.Reader) ([]byte, error) {
	return ReadBodyLimit(r, MaxResponseBytes)
}

// ReadBodyLimit reads up to limit bytes from r. Unlike a plain io.LimitReader,
// it does NOT silently truncate: a body larger than limit is reported as an
// error so a caller never decodes a partial page — that silent truncation is
// the exact data-loss defect these connectors were fixed to avoid. Genuine
// read errors are propagated unchanged.
func ReadBodyLimit(r io.Reader, limit int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	// Read one byte past the limit so an over-cap body is detectable rather
	// than indistinguishable from one that lands exactly on the boundary.
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("connutil: response body exceeds %d-byte cap", limit)
	}
	return buf, nil
}
