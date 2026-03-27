package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Environment represents the deployment target.
type Environment string

const (
	Local      Environment = "local"
	Staging    Environment = "staging"
	Production Environment = "production"
)

// TraceExtractorFn extracts trace context (trace_id, span_id) from a request context.
// Pluggable for OpenTelemetry or other tracing systems.
type TraceExtractorFn func(ctx context.Context) []slog.Attr

// loggerConfig holds configuration for logger creation.
type loggerConfig struct {
	level          slog.Level
	output         io.Writer
	traceExtractor TraceExtractorFn
}

// Option is a functional option for logger configuration.
type Option func(*loggerConfig)

// WithLevel overrides the default log level for the environment.
func WithLevel(level slog.Level) Option {
	return func(cfg *loggerConfig) {
		cfg.level = level
	}
}

// WithOutput overrides the default output writer (stdout).
func WithOutput(w io.Writer) Option {
	return func(cfg *loggerConfig) {
		cfg.output = w
	}
}

// WithTraceExtractor sets a function to extract trace attributes from context.
// Used in staging/production to inject trace_id and span_id into log entries.
func WithTraceExtractor(fn TraceExtractorFn) Option {
	return func(cfg *loggerConfig) {
		cfg.traceExtractor = fn
	}
}

// New creates a configured *slog.Logger for the given environment.
//
// Environment behavior:
//   - local:      Debug level, text format (human-readable)
//   - staging:    Info level, JSON format, trace attributes when available
//   - production: Error level, JSON format, trace attributes when available
func New(env Environment, opts ...Option) *slog.Logger {
	cfg := defaultConfig(env)
	for _, opt := range opts {
		opt(&cfg)
	}

	levelVar := &slog.LevelVar{}
	levelVar.Set(cfg.level)

	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{
		Level: levelVar,
	}

	switch env {
	case Local:
		handler = slog.NewTextHandler(cfg.output, handlerOpts)
	case Staging, Production:
		handler = slog.NewJSONHandler(cfg.output, handlerOpts)
		if cfg.traceExtractor != nil {
			handler = &traceHandler{
				inner:     handler,
				extractor: cfg.traceExtractor,
			}
		}
	default:
		handler = slog.NewJSONHandler(cfg.output, handlerOpts)
	}

	return slog.New(handler)
}

// defaultConfig returns the default configuration for an environment.
func defaultConfig(env Environment) loggerConfig {
	cfg := loggerConfig{
		output: os.Stdout,
	}

	switch env {
	case Local:
		cfg.level = slog.LevelDebug
	case Staging:
		cfg.level = slog.LevelInfo
	case Production:
		cfg.level = slog.LevelError
	default:
		cfg.level = slog.LevelInfo
	}

	return cfg
}

// traceHandler wraps a slog.Handler to inject trace attributes.
type traceHandler struct {
	inner     slog.Handler
	extractor TraceExtractorFn
}

func (h *traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *traceHandler) Handle(ctx context.Context, record slog.Record) error {
	if h.extractor != nil {
		attrs := h.extractor(ctx)
		for _, attr := range attrs {
			record.AddAttrs(attr)
		}
	}
	return h.inner.Handle(ctx, record)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{
		inner:     h.inner.WithAttrs(attrs),
		extractor: h.extractor,
	}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{
		inner:     h.inner.WithGroup(name),
		extractor: h.extractor,
	}
}
