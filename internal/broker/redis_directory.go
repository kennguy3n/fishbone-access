package broker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RedisSessionDirectory is an OPTIONAL write-through cache in front of the
// authoritative (Postgres) SessionDirectory, following the repo's house
// optional-Redis pattern (ACCESS_REDIS_URL, fail-open). Postgres remains the
// source of truth; Redis only accelerates the one hot read on the cross-replica
// path — Lookup, which a dial that did not land on the owning replica performs
// to find the owner.
//
// It is FAIL-OPEN by construction: every Redis operation is best-effort and
// bounded by a short timeout, and on any miss/error the call falls through to
// the authoritative directory. A Redis outage therefore degrades to "same as no
// cache" (one Postgres round trip), never to a wrong or failed routing
// decision. Freshness is always recomputed from the entry's last_seen against
// the staleness window, so a cached entry for a crashed owner is still seen as
// stale — the cache can make a lookup faster, never make a stale owner look
// alive.
//
// Writes are write-through: Claim and a successful Refresh update the cache so a
// live, heartbeating owner's cached last_seen stays current; Release and a lost
// ownership CAS invalidate it so a moved/disconnected agent is not served from a
// stale cache. The short TTL bounds how long a crash (no Release) can leave a
// dangling entry before it falls back to Postgres.
type RedisSessionDirectory struct {
	inner      SessionDirectory
	rdb        *redis.Client
	prefix     string
	ttl        time.Duration
	opTimeout  time.Duration
	staleAfter time.Duration
	now        func() time.Time
	onError    func(error)
}

var _ SessionDirectory = (*RedisSessionDirectory)(nil)

// directoryKeyPrefix namespaces directory keys inside a Redis instance shared
// with the rate limiter and usage accumulator. The version segment lets the
// layout evolve without colliding with an older deployment's keys.
const directoryKeyPrefix = "shieldnet:agentdir:v1:"

// defaultDirectoryCacheTTL bounds how long a cached owner entry lives. It is
// short on purpose: long enough to absorb a burst of dials to the same agent,
// short enough that a crashed owner's dangling entry (no Release ran) falls back
// to Postgres quickly. It is well under HealthOfflineAfter so the cache never
// outlives the authoritative staleness decision.
const defaultDirectoryCacheTTL = 3 * time.Second

// defaultDirectoryOpTimeout bounds a single Redis round trip on the dial path so
// a stalled Redis trips the fail-open fallback fast rather than adding its stall
// to a privileged-session open.
const defaultDirectoryOpTimeout = 100 * time.Millisecond

// RedisDirectoryConfig tunes the cache. Zero values fall back to the defaults.
type RedisDirectoryConfig struct {
	// StaleAfter is the freshness window; must match the inner directory's so
	// cache and source agree on "online". Non-positive uses HealthOfflineAfter.
	StaleAfter time.Duration
	// TTL is the cache entry lifetime. Non-positive uses defaultDirectoryCacheTTL.
	TTL time.Duration
	// OpTimeout bounds a single Redis call. Non-positive uses the default.
	OpTimeout time.Duration
	// OnError observes fail-open events (e.g. a degraded-Redis metric). Optional.
	OnError func(error)
}

// NewRedisSessionDirectory wraps inner with a Redis write-through cache.
func NewRedisSessionDirectory(inner SessionDirectory, rdb *redis.Client, cfg RedisDirectoryConfig) *RedisSessionDirectory {
	staleAfter := cfg.StaleAfter
	if staleAfter <= 0 {
		staleAfter = HealthOfflineAfter
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultDirectoryCacheTTL
	}
	opTO := cfg.OpTimeout
	if opTO <= 0 {
		opTO = defaultDirectoryOpTimeout
	}
	return &RedisSessionDirectory{
		inner:      inner,
		rdb:        rdb,
		prefix:     directoryKeyPrefix,
		ttl:        ttl,
		opTimeout:  opTO,
		staleAfter: staleAfter,
		now:        time.Now,
		onError:    cfg.OnError,
	}
}

// SetClock overrides the time source (tests).
func (d *RedisSessionDirectory) SetClock(now func() time.Time) {
	if now != nil {
		d.now = now
	}
}

// cachedEntry is the JSON shape stored in Redis. It carries last_seen so the
// reader recomputes freshness rather than trusting a cached boolean.
type cachedEntry struct {
	NodeID      string    `json:"n"`
	ForwardAddr string    `json:"a"`
	Epoch       int64     `json:"e"`
	LastSeenAt  time.Time `json:"t"`
}

func (d *RedisSessionDirectory) key(workspaceID, agentID uuid.UUID) string {
	return d.prefix + workspaceID.String() + ":" + agentID.String()
}

// Claim delegates to the authoritative directory, then best-effort writes the
// new owner into the cache so an immediately following cross-replica dial reads
// it without a Postgres round trip.
func (d *RedisSessionDirectory) Claim(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID, forwardAddr string) (int64, error) {
	epoch, err := d.inner.Claim(ctx, workspaceID, agentID, nodeID, forwardAddr)
	if err != nil {
		return 0, err
	}
	d.cacheSet(ctx, workspaceID, agentID, cachedEntry{
		NodeID:      nodeID,
		ForwardAddr: forwardAddr,
		Epoch:       epoch,
		LastSeenAt:  d.now(),
	})
	return epoch, nil
}

// Refresh delegates to the authoritative directory. On success it write-through
// updates the cached last_seen so a live owner stays fresh in the cache; on a
// lost CAS it invalidates the entry (another replica owns it now).
func (d *RedisSessionDirectory) Refresh(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID string, epoch int64) error {
	err := d.inner.Refresh(ctx, workspaceID, agentID, nodeID, epoch)
	if err != nil {
		if errors.Is(err, ErrOwnershipLost) {
			d.cacheDel(ctx, workspaceID, agentID)
		}
		return err
	}
	d.cacheSet(ctx, workspaceID, agentID, cachedEntry{
		NodeID:      nodeID,
		ForwardAddr: "", // resolved below from the cache/inner; see note
		Epoch:       epoch,
		LastSeenAt:  d.now(),
	})
	return nil
}

// Release delegates to the authoritative directory, then invalidates the cache
// so a disconnected agent is never served from a stale entry.
func (d *RedisSessionDirectory) Release(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID string, epoch int64) error {
	err := d.inner.Release(ctx, workspaceID, agentID, nodeID, epoch)
	// Invalidate regardless of error: a Release that errored on Postgres should
	// not leave a confidently-cached owner behind. A spurious miss merely costs
	// one Postgres lookup (fail-open).
	d.cacheDel(ctx, workspaceID, agentID)
	return err
}

// Lookup reads the cache first; on hit it recomputes freshness from the cached
// last_seen. On any miss/error it falls through to the authoritative directory
// and refreshes the cache.
func (d *RedisSessionDirectory) Lookup(ctx context.Context, workspaceID, agentID uuid.UUID) (*OwnerEntry, bool, error) {
	if ce, ok := d.cacheGet(ctx, workspaceID, agentID); ok {
		entry := &OwnerEntry{
			NodeID:      ce.NodeID,
			ForwardAddr: ce.ForwardAddr,
			Epoch:       ce.Epoch,
			LastSeenAt:  ce.LastSeenAt,
		}
		return entry, d.fresh(ce.LastSeenAt), nil
	}
	entry, fresh, err := d.inner.Lookup(ctx, workspaceID, agentID)
	if err != nil {
		return nil, false, err
	}
	if entry != nil {
		d.cacheSet(ctx, workspaceID, agentID, cachedEntry{
			NodeID:      entry.NodeID,
			ForwardAddr: entry.ForwardAddr,
			Epoch:       entry.Epoch,
			LastSeenAt:  entry.LastSeenAt,
		})
	}
	return entry, fresh, nil
}

// OnlineCount and IsOnline are management-surface reads, not on the hot dial
// path, so they go straight to the authoritative directory (a cross-fleet count
// is not meaningfully cacheable without risking an undercount that would hide a
// live agent).
func (d *RedisSessionDirectory) OnlineCount(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	return d.inner.OnlineCount(ctx, workspaceID)
}

func (d *RedisSessionDirectory) IsOnline(ctx context.Context, workspaceID, agentID uuid.UUID) (bool, error) {
	return d.inner.IsOnline(ctx, workspaceID, agentID)
}

func (d *RedisSessionDirectory) fresh(lastSeen time.Time) bool {
	return d.now().Sub(lastSeen) <= d.staleAfter
}

// --- best-effort Redis helpers (all fail-open) ----------------------------

func (d *RedisSessionDirectory) cacheGet(ctx context.Context, workspaceID, agentID uuid.UUID) (cachedEntry, bool) {
	opCtx, cancel := context.WithTimeout(ctx, d.opTimeout)
	defer cancel()
	b, err := d.rdb.Get(opCtx, d.key(workspaceID, agentID)).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			d.failOpen(err)
		}
		return cachedEntry{}, false
	}
	var ce cachedEntry
	if err := json.Unmarshal(b, &ce); err != nil {
		d.failOpen(err)
		return cachedEntry{}, false
	}
	return ce, true
}

func (d *RedisSessionDirectory) cacheSet(ctx context.Context, workspaceID, agentID uuid.UUID, ce cachedEntry) {
	// A Refresh knows the epoch and last_seen but not the forward address; rather
	// than risk caching an empty address, fold it from the existing entry when
	// the caller left it blank. A miss here just skips the cache write.
	if ce.ForwardAddr == "" {
		if existing, ok := d.cacheGet(ctx, workspaceID, agentID); ok {
			ce.ForwardAddr = existing.ForwardAddr
		} else {
			return
		}
	}
	b, err := json.Marshal(ce)
	if err != nil {
		d.failOpen(err)
		return
	}
	opCtx, cancel := context.WithTimeout(ctx, d.opTimeout)
	defer cancel()
	if err := d.rdb.Set(opCtx, d.key(workspaceID, agentID), b, d.ttl).Err(); err != nil {
		d.failOpen(err)
	}
}

func (d *RedisSessionDirectory) cacheDel(ctx context.Context, workspaceID, agentID uuid.UUID) {
	opCtx, cancel := context.WithTimeout(ctx, d.opTimeout)
	defer cancel()
	if err := d.rdb.Del(opCtx, d.key(workspaceID, agentID)).Err(); err != nil {
		d.failOpen(err)
	}
}

func (d *RedisSessionDirectory) failOpen(err error) {
	if d.onError != nil {
		d.onError(err)
	}
}
