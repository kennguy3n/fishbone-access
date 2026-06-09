package gateway

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// SessionIntentSource yields the durable, cross-process control intent for a
// set of sessions in a workspace. *pam.SessionManager satisfies it; declaring
// it as an interface here keeps the reconciler unit-testable with a fake and
// keeps the dependency pointing gateway → pam.
type SessionIntentSource interface {
	SessionIntents(ctx context.Context, workspaceID uuid.UUID, sessionIDs []uuid.UUID) (map[uuid.UUID]pam.SessionIntent, error)
}

// SessionReconciler bridges control-plane session-control decisions onto this
// gateway process's in-process sessions. Pause/terminate issued through the API
// (a different process) land only in the database — the Paused flag and the
// session State — so this loop periodically reconciles the durable intent for
// every session this process is proxying against the live hub: a session whose
// row is no longer active is terminated, and the soft-pause gate is raised or
// lowered to match the Paused flag. It is the cross-process half of the live
// session-control feature; the in-process fast path (a colocated manager
// driving the hub directly) still applies immediately, so this loop is the
// catch-up for the distributed deployment.
type SessionReconciler struct {
	hub      *SessionHub
	src      SessionIntentSource
	interval time.Duration
}

// NewSessionReconciler builds a reconciler. interval <= 0 selects a 2s default,
// which bounds the worst-case latency between an operator clicking
// pause/terminate in the console and the gateway acting on a session it proxies.
func NewSessionReconciler(hub *SessionHub, src SessionIntentSource, interval time.Duration) *SessionReconciler {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &SessionReconciler{hub: hub, src: src, interval: interval}
}

// Run reconciles on a ticker until ctx is cancelled. It is resilient: a query
// error for one workspace is logged and the loop continues, so a transient DB
// blip never stops the reconciler.
func (r *SessionReconciler) Run(ctx context.Context) {
	if r == nil || r.hub == nil || r.src == nil {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcileOnce(ctx)
		}
	}
}

// reconcileOnce applies the current durable intent to every in-process session.
func (r *SessionReconciler) reconcileOnce(ctx context.Context) {
	for workspaceID, ids := range r.hub.snapshotByWorkspace() {
		intents, err := r.src.SessionIntents(ctx, workspaceID, ids)
		if err != nil {
			logger.Warnf(ctx, "gateway: reconcile session intents for workspace %s: %v", workspaceID, err)
			continue
		}
		for id, intent := range intents {
			switch {
			case !intent.Active:
				// Row terminated/closed out from under the proxy → sever it.
				r.hub.Terminate(id)
			case intent.Paused:
				r.hub.Pause(id)
			default:
				r.hub.Resume(id)
			}
		}
	}
}
