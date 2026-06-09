package access

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Sync mode labels recorded on a SyncResult, describing which path the
// orchestrator actually took.
const (
	// SyncModeFull is a full enumeration: either the connector has no delta
	// capability, or it is delta-capable but no cursor was stored yet.
	SyncModeFull = "full"
	// SyncModeDelta is a pure incremental sync against a stored delta cursor.
	SyncModeDelta = "delta"
	// SyncModeDeltaThenFullFallback is a delta attempt that the provider
	// rejected (cursor expired / 410 Gone), after which the orchestrator
	// dropped the cursor and ran a full enumeration.
	SyncModeDeltaThenFullFallback = "delta_then_full_fallback"
)

// IdentityBatchHandler consumes one page of identities the orchestrator pulls
// from a connector. removedExternalIDs carries provider-reported tombstones
// (always non-nil; empty for full-sync pages, which have no tombstone channel).
// Returning an error aborts the sync immediately; the orchestrator leaves the
// stored cursor untouched so the next run resumes from the SAME checkpoint
// (idempotent partial-failure recovery).
type IdentityBatchHandler func(batch []*Identity, removedExternalIDs []string) error

// SyncResult summarises one orchestrated sync for the caller's logs/metrics.
type SyncResult struct {
	Mode           string
	Batches        int
	IdentitiesSeen int
	RemovedSeen    int
	// FinalDeltaLink is the cursor persisted for the next run: the provider's
	// final delta link after a delta sync, or the freshly-seeded baseline
	// cursor after a full sync of a delta-capable connector. Empty when the
	// connector has no delta capability and emitted no resumable cursor.
	FinalDeltaLink string
}

// IdentityDeltaSyncOrchestrator drives an identity sync with correct
// delta→full fallback and idempotent cursor management, layered over the
// existing SyncStateStore. It is the missing orchestration layer the reference
// (ShieldNet 360) calls out: connectors expose the raw delta/full primitives,
// but the platform — not each connector — owns the policy of when to use delta,
// when to fall back, and how the watermark cursor advances.
//
// Cursor invariants (the heart of the hardening):
//
//   - A delta sync persists the provider's final delta link ONLY after the
//     whole stream is consumed without error. A mid-stream handler error aborts
//     with the stored cursor unchanged, so the next run re-enters delta from the
//     same watermark (no skipped or double-applied pages from the platform's
//     side; the handler is responsible for its own upsert idempotency).
//   - A provider that rejects the cursor (ErrDeltaTokenExpired / 410 Gone)
//     causes the cursor to be dropped and a full enumeration to run, after which
//     a fresh baseline cursor is seeded for the next run.
//   - A full sync of a delta-capable connector seeds a baseline cursor on
//     success; a seed failure is logged but never fails the sync (the next run
//     simply does another full sync).
type IdentityDeltaSyncOrchestrator struct {
	cursors *SyncStateStore
}

// NewIdentityDeltaSyncOrchestrator builds an orchestrator over the given cursor
// store.
func NewIdentityDeltaSyncOrchestrator(cursors *SyncStateStore) *IdentityDeltaSyncOrchestrator {
	return &IdentityDeltaSyncOrchestrator{cursors: cursors}
}

// Run executes one sync for (workspaceID, connectorID, syncType) and returns a
// summary. It chooses delta vs full based on the connector's capabilities and
// the stored cursor, handles the 410-Gone fallback, and advances the cursor
// per the invariants documented on the type.
func (o *IdentityDeltaSyncOrchestrator) Run(
	ctx context.Context,
	workspaceID, connectorID uuid.UUID,
	syncType string,
	connector AccessConnector,
	cfg, secrets map[string]interface{},
	handler IdentityBatchHandler,
) (*SyncResult, error) {
	if o == nil || o.cursors == nil {
		return nil, fmt.Errorf("access: orchestrator not initialised")
	}
	if connector == nil {
		return nil, fmt.Errorf("access: orchestrator: connector is required")
	}
	if handler == nil {
		return nil, fmt.Errorf("access: orchestrator: handler is required")
	}
	syncType = normalizeSyncType(syncType)

	cursor, err := o.cursors.Load(ctx, workspaceID, connectorID, syncType)
	if err != nil {
		return nil, fmt.Errorf("access: orchestrator: load cursor: %w", err)
	}

	deltaSyncer, _ := connector.(IdentityDeltaSyncer)
	result := &SyncResult{}

	// Delta path: only when the connector implements the optional interface AND
	// a cursor is stored. A first run (empty cursor) always goes full.
	if deltaSyncer != nil && cursor != "" {
		finalLink, derr := o.runDelta(ctx, deltaSyncer, cfg, secrets, cursor, handler, result)
		if derr == nil {
			result.Mode = SyncModeDelta
			result.FinalDeltaLink = finalLink
			// Persist the new watermark only after the whole stream succeeded.
			if err := o.cursors.Save(ctx, workspaceID, connectorID, syncType, finalLink); err != nil {
				return result, fmt.Errorf("access: orchestrator: persist delta cursor: %w", err)
			}
			return result, nil
		}
		if !errors.Is(derr, ErrDeltaTokenExpired) {
			// Partial failure (handler error, transport error). Leave the cursor
			// intact so the next run resumes delta from the same watermark. Label
			// the partial result as a delta attempt so a caller logging the
			// returned SyncResult alongside the error can see which path failed.
			result.Mode = SyncModeDelta
			return result, fmt.Errorf("access: orchestrator: delta sync: %w", derr)
		}
		// Cursor expired / 410 Gone: we've committed to dropping the cursor and
		// falling back to a full enumeration, so stamp the mode before the Clear
		// — a Clear failure then still returns a result that accurately reflects
		// the attempted delta-then-fallback path.
		result.Mode = SyncModeDeltaThenFullFallback
		if err := o.cursors.Clear(ctx, workspaceID, connectorID, syncType); err != nil {
			return result, fmt.Errorf("access: orchestrator: drop expired cursor: %w", err)
		}
		logger.Infof(ctx, "access: orchestrator: delta cursor expired for connector %s; falling back to full sync", connectorID)
	} else {
		result.Mode = SyncModeFull
	}

	// Full path. For a non-delta connector we resume from the stored pagination
	// cursor (preserving the connector's own resumable-pagination behaviour);
	// for a delta-capable connector the full path is always a fresh enumeration
	// (cursor was empty or just dropped), so we start from "".
	fullCheckpoint := ""
	if deltaSyncer == nil {
		fullCheckpoint = cursor
	}
	latestCheckpoint, err := o.runFull(ctx, connector, cfg, secrets, fullCheckpoint, handler, result)
	if err != nil {
		return result, fmt.Errorf("access: orchestrator: full sync: %w", err)
	}

	// Advance the cursor after a successful full sync.
	if deltaSyncer != nil {
		// Seed a baseline delta cursor so the next run can go incremental. A
		// seed failure is non-fatal: the next run just does another full sync.
		seeded, seedErr := deltaSyncer.InitialDeltaCursor(ctx, cfg, secrets)
		if seedErr != nil {
			logger.Warnf(ctx, "access: orchestrator: seed delta cursor failed for connector %s: %v", connectorID, seedErr)
			seeded = ""
		}
		result.FinalDeltaLink = seeded
		if err := o.persistFullCursor(ctx, workspaceID, connectorID, syncType, seeded); err != nil {
			return result, err
		}
		return result, nil
	}

	// Non-delta connector: persist the latest pagination cursor only when it
	// actually advanced, mirroring the prior job-processor behaviour.
	result.FinalDeltaLink = latestCheckpoint
	if latestCheckpoint != fullCheckpoint {
		if err := o.cursors.Save(ctx, workspaceID, connectorID, syncType, latestCheckpoint); err != nil {
			return result, fmt.Errorf("access: orchestrator: persist pagination cursor: %w", err)
		}
	}
	return result, nil
}

// runDelta streams the connector's delta pages into handler, accumulating
// counters on result. It returns the provider's final delta link.
func (o *IdentityDeltaSyncOrchestrator) runDelta(
	ctx context.Context,
	deltaSyncer IdentityDeltaSyncer,
	cfg, secrets map[string]interface{},
	cursor string,
	handler IdentityBatchHandler,
	result *SyncResult,
) (string, error) {
	return deltaSyncer.SyncIdentitiesDelta(ctx, cfg, secrets, cursor,
		func(batch []*Identity, removedExternalIDs []string, _ string) error {
			removed := removedExternalIDs
			if removed == nil {
				removed = []string{}
			}
			if err := handler(batch, removed); err != nil {
				return err
			}
			result.Batches++
			result.IdentitiesSeen += len(batch)
			result.RemovedSeen += len(removed)
			return nil
		})
}

// runFull streams the connector's full enumeration into handler. Full-sync
// pages have no tombstone channel, so removedExternalIDs is always the empty
// slice. It returns the latest non-empty pagination cursor the connector
// emitted.
func (o *IdentityDeltaSyncOrchestrator) runFull(
	ctx context.Context,
	connector AccessConnector,
	cfg, secrets map[string]interface{},
	checkpoint string,
	handler IdentityBatchHandler,
	result *SyncResult,
) (string, error) {
	latest := checkpoint
	err := connector.SyncIdentities(ctx, cfg, secrets, checkpoint,
		func(batch []*Identity, nextCheckpoint string) error {
			if err := handler(batch, []string{}); err != nil {
				return err
			}
			result.Batches++
			result.IdentitiesSeen += len(batch)
			if nextCheckpoint != "" {
				latest = nextCheckpoint
			}
			return nil
		})
	if err != nil {
		return latest, err
	}
	return latest, nil
}

// persistFullCursor stores the seeded baseline cursor after a full sync of a
// delta-capable connector. An empty seed clears any stored cursor so the next
// run stays in full mode rather than entering delta with a bogus watermark.
func (o *IdentityDeltaSyncOrchestrator) persistFullCursor(ctx context.Context, workspaceID, connectorID uuid.UUID, syncType, seeded string) error {
	if seeded == "" {
		if err := o.cursors.Clear(ctx, workspaceID, connectorID, syncType); err != nil {
			return fmt.Errorf("access: orchestrator: clear cursor after full sync: %w", err)
		}
		return nil
	}
	if err := o.cursors.Save(ctx, workspaceID, connectorID, syncType, seeded); err != nil {
		return fmt.Errorf("access: orchestrator: seed cursor after full sync: %w", err)
	}
	return nil
}
