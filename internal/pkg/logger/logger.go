// Package logger is a thin structured-logging façade over log/slog. It exists
// so service code depends on a stable internal API rather than slog directly,
// which keeps a future swap (e.g. to a JSON production handler with sampling)
// to a single file.
package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
)

// base holds the active logger in an atomic pointer so SetLevel (a writer) and
// the Infof/Warnf/Errorf logging calls (readers) are race-free even if the
// level is adjusted concurrently with logging.
var base atomic.Pointer[slog.Logger]

func init() {
	base.Store(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
}

// SetLevel adjusts the global log level. Safe to call concurrently with logging.
func SetLevel(level slog.Level) {
	base.Store(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

// Infof logs at info level.
func Infof(ctx context.Context, format string, args ...any) {
	base.Load().InfoContext(ctx, sprintf(format, args...))
}

// Warnf logs at warn level.
func Warnf(ctx context.Context, format string, args ...any) {
	base.Load().WarnContext(ctx, sprintf(format, args...))
}

// Errorf logs at error level.
func Errorf(ctx context.Context, format string, args ...any) {
	base.Load().ErrorContext(ctx, sprintf(format, args...))
}

func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
