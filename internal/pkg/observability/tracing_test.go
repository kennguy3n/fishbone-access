package observability

import (
	"context"
	"testing"
)

func TestInitTracerDisabledByDefault(t *testing.T) {
	// Ensure the opt-in env is not set for this case.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, enabled, err := InitTracer(context.Background(), "test")
	if err != nil {
		t.Fatalf("InitTracer err = %v, want nil", err)
	}
	if enabled {
		t.Fatal("tracing should be disabled when OTEL_EXPORTER_OTLP_ENDPOINT is unset")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("no-op shutdown err = %v, want nil", err)
	}
}

func TestInitTracerEnabledWithEndpoint(t *testing.T) {
	// The OTLP/gRPC exporter connects lazily, so InitTracer succeeds without a
	// live collector; this verifies the opt-in path installs a provider.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	shutdown, enabled, err := InitTracer(context.Background(), "test")
	if err != nil {
		t.Fatalf("InitTracer err = %v, want nil", err)
	}
	if !enabled {
		t.Fatal("tracing should be enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	cancel() // shutdown should not hang even with an already-cancelled context
	_ = shutdown(ctx)
}
