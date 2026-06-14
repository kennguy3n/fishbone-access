package observability

import (
	"context"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

// Distributed tracing.
//
// Tracing is OPT-IN and standards-native: it is wired only when the operator
// sets the standard OTEL_EXPORTER_OTLP_ENDPOINT (the same env every OTLP
// collector/agent uses). Absent that, InitTracer installs no provider and
// TracingEnabled reports false, so there is zero tracing overhead and no extra
// network dependency in the default deployment — the SME-friendly posture. When
// an operator points OTEL_* at their collector, request spans (and any
// downstream spans that use the global tracer) flow out via OTLP/gRPC with no
// code change. All exporter knobs (endpoint, headers, TLS, sampling) come from
// the standard OTEL_* environment so we don't reinvent configuration.

// InitTracer configures the global OpenTelemetry tracer provider for
// serviceName. It returns (shutdown, enabled, err): when OTEL_EXPORTER_OTLP_ENDPOINT
// is unset it is a no-op with enabled=false; otherwise it installs an OTLP/gRPC
// batch exporter and W3C trace-context propagation, and the returned shutdown
// MUST be called on exit to flush buffered spans.
func InitTracer(ctx context.Context, serviceName string) (shutdown func(context.Context) error, enabled bool, err error) {
	noop := func(context.Context) error { return nil }
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return noop, false, nil
	}

	exp, err := otlptracegrpc.New(ctx)
	if err != nil {
		return noop, false, fmt.Errorf("observability: otlp trace exporter: %w", err)
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		// Close the exporter's gRPC connection before bailing — we own it from
		// the point New succeeded, and the returned noop shutdown won't.
		_ = exp.Shutdown(ctx)
		return noop, false, fmt.Errorf("observability: otel resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return tp.Shutdown, true, nil
}

// TracingMiddleware returns the Gin middleware that opens a server span per
// request, named by the matched route template (low cardinality, same rationale
// as the metrics labels). Mount it only when InitTracer reported enabled, so a
// no-provider deployment pays nothing.
func TracingMiddleware(serviceName string) gin.HandlerFunc {
	return otelgin.Middleware(serviceName, otelgin.WithSpanNameFormatter(func(c *gin.Context) string {
		if r := c.FullPath(); r != "" {
			return c.Request.Method + " " + r
		}
		return c.Request.Method
	}))
}
