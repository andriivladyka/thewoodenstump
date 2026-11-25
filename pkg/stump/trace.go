package stump

import (
	"context"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// initTracing sends spans over OTLP/HTTP when OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
// (or OTEL_EXPORTER_OTLP_ENDPOINT) is set; otherwise tracing is off.
func initTracing(ctx context.Context, name string) func(context.Context) error {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return func(context.Context) error { return nil }
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return func(context.Context) error { return nil }
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", name),
		attribute.String("service.namespace", "stump"),
		attribute.String("deployment.environment.name", Env("STUMP_ENVIRONMENT", "lab")),
	)
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())))
	otel.SetTracerProvider(tp)
	return tp.Shutdown
}

// HTTPClient passes the trace context on to the services it calls.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: otelhttp.NewTransport(http.DefaultTransport)}
}

func traced(name string, h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, name, otelhttp.WithFilter(func(r *http.Request) bool {
		return r.URL.Path != "/healthz" && r.URL.Path != "/metrics"
	}))
}
