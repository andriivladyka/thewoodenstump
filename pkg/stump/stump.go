// Package stump holds what every service shares: config, HTTP server,
// JSON helpers, Postgres and NATS connections.
package stump

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

// Env returns the variable or def when it is unset.
func Env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// MustEnv returns the variable or exits.
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing environment variable", "name", key)
		os.Exit(2)
	}
	return v
}

// EnvBool reads true/false, 1/0, yes/no.
func EnvBool(key string, def bool) bool {
	switch strings.ToLower(Env(key, "")) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// EnvDuration reads a Go duration such as 1h or 168h.
func EnvDuration(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(Env(key, "")); err == nil {
		return d
	}
	return def
}

// App is one service process.
type App struct {
	Name string
	Log  *slog.Logger
	Mux  *http.ServeMux
	ctx  context.Context
	stop context.CancelFunc
}

// New sets up JSON logging and a context cancelled on SIGTERM.
func New(name string) *App {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", name)
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	a := &App{Name: name, Log: log, Mux: http.NewServeMux(), ctx: ctx, stop: stop}
	a.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	a.Mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		metrics.WritePrometheus(w, true)
	})
	return a
}

// Context is cancelled when the process is asked to stop.
func (a *App) Context() context.Context { return a.ctx }

// Serve runs the HTTP server on STUMP_LISTEN (default :8080) until stopped.
func (a *App) Serve() {
	defer a.stop()
	srv := &http.Server{
		Addr:              Env("STUMP_LISTEN", ":8080"),
		Handler:           a.instrument(a.Mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-a.ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	a.Log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.Log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) { w.code = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (a *App) instrument(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			h.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(sw, r)
		metrics.GetOrCreateCounter(fmt.Sprintf(`stump_http_requests_total{service=%q,method=%q,code="%d"}`, a.Name, r.Method, sw.code)).Inc()
		metrics.GetOrCreateHistogram(fmt.Sprintf(`stump_http_request_duration_seconds{service=%q}`, a.Name)).UpdateDuration(start)
	})
}

// JSON writes v with the status code.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// Problem is the error body every service returns.
type Problem struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Detail  any    `json:"detail,omitempty"`
}

// Error writes a Problem.
func Error(w http.ResponseWriter, status int, code, msg string) {
	JSON(w, status, Problem{Error: code, Message: msg})
}

// ReadJSON decodes at most max bytes into v and rejects unknown fields.
func ReadJSON(r *http.Request, max int64, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// Retry calls f until it succeeds or ctx ends, waiting between tries.
func Retry(ctx context.Context, what string, f func() error) error {
	wait := time.Second
	for {
		err := f()
		if err == nil {
			return nil
		}
		slog.Warn("retrying", "what", what, "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait < 30*time.Second {
			wait *= 2
		}
	}
}
