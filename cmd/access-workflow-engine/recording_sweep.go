package main

import (
	"context"
	"os"
	"strconv"

	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/pkg/observability"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/workflow_engine"
	"github.com/kennguy3n/fishbone-access/internal/services/recordings"
)

// recordingReplayStore is the replay backend the sweep needs: read (to verify
// integrity at index time) AND delete (to tier expired blobs). Both the
// filesystem and S3 stores satisfy it.
type recordingReplayStore interface {
	recordings.ReplayReader
	recordings.ReplayDeleter
}

// buildRecordingReplayStore opens the replay backend from the same PAM_REPLAY_*
// environment the gateway writes recordings to and the API reads them from, so
// the sweep tiers blobs out of the IDENTICAL store. When a per-workspace KMS
// master key is configured it wraps the store in transparent per-workspace
// decryption, so the index-time integrity check reads the same plaintext frames
// the gateway recorded (the decorator also opens legacy plaintext blobs
// unchanged). Returns nil when no backend can be opened — the sweep then still
// indexes from DB facts and simply skips pruning (which needs a deleter),
// rather than failing the engine boot.
func buildRecordingReplayStore(ctx context.Context, gdb *gorm.DB) recordingReplayStore {
	base, err := gateway.OpenReplayStoreFromEnv(ctx)
	if err != nil {
		logger.Warnf(ctx, "access-workflow-engine: recordings: replay store init: %v (prune disabled)", err)
		return nil
	}
	sealer := recordingReplaySealer()
	if sealer == nil {
		return base
	}
	store, werr := gateway.WrapWithEncryption(base, sealer, gateway.NewGormSessionWorkspaceResolver(gdb))
	if werr != nil {
		logger.Warnf(ctx, "access-workflow-engine: recordings: replay at-rest decryption init: %v (prune disabled)", werr)
		return nil
	}
	return store
}

// recordingReplaySealer builds the per-workspace credential encryptor used to
// open at-rest-encrypted recording blobs, from the same ACCESS_KMS_* env the
// gateway and API read. Returns nil when no KMS master key is set (plaintext
// blobs), matching the gateway's write-side gate.
func recordingReplaySealer() access.CredentialEncryptor {
	master := os.Getenv("ACCESS_KMS_MASTER_KEY")
	if master == "" {
		return nil
	}
	keyVersion := 1
	if v := os.Getenv("ACCESS_KMS_KEY_VERSION"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n >= 0 {
			keyVersion = n
		}
	}
	enc, err := access.CredentialEncryptorFromConfig(master, keyVersion, os.Getenv("ACCESS_CREDENTIAL_DEK"))
	if err != nil {
		return nil
	}
	return enc
}

// newRecordingSweeper assembles the background index + retention-prune sweep for
// the recordings forensic store. It mirrors the review scheduler's wiring:
// fail-open, hibernation-gated, bounded per-workspace work. Returns nil (no
// sweeper) when the feature is disabled, so the caller simply skips launching
// it.
func newRecordingSweeper(
	ctx context.Context,
	cfg config.RecordingsConfig,
	gdb *gorm.DB,
	gate recordings.HibernationGate,
	metrics *observability.Metrics,
) (*recordings.Sweeper, error) {
	if !cfg.SweepEnabled {
		logger.Infof(ctx, "access-workflow-engine: recordings sweep DISABLED (ACCESS_RECORDING_SWEEP_ENABLED=false)")
		return nil, nil
	}

	var opts []recordings.Option
	if metrics != nil {
		opts = append(opts, recordings.WithMetrics(metrics))
	}
	store := buildRecordingReplayStore(ctx, gdb)
	if store != nil {
		// The reader enriches the index with keystroke text + a live integrity
		// check; the deleter lets the sweep actually tier expired blobs.
		opts = append(opts, recordings.WithReplayReader(store), recordings.WithReplayDeleter(store))
	} else {
		logger.Warnf(ctx, "access-workflow-engine: recordings: no replay store; sweep will index metadata only and skip pruning")
	}

	svc := recordings.NewService(gdb, opts...)
	sweeper, err := recordings.NewSweeper(svc, workflow_engine.NewGormWorkspaceLister(gdb), recordings.SweepConfig{
		Interval:             cfg.SweepInterval,
		DefaultRetentionDays: cfg.DefaultRetentionDays,
		IndexBatch:           cfg.IndexBatch,
		PruneBatch:           cfg.PruneBatch,
	})
	if err != nil {
		return nil, err
	}
	// metrics is optional (guarded above); only observe dormant-skips when it is
	// wired, so the skip closure never dereferences a nil Metrics at runtime.
	var onSkipDormant func()
	if metrics != nil {
		onSkipDormant = func() { metrics.IncPeriodicJobSkipped("recording_sweep") }
	}
	sweeper.WithHibernationGate(gate, onSkipDormant)
	logger.Infof(ctx, "access-workflow-engine: recordings sweep enabled (interval=%s default_retention_days=%d)",
		cfg.SweepInterval, cfg.DefaultRetentionDays)
	return sweeper, nil
}
