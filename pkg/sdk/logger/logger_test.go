package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Local(t *testing.T) {
	var buf bytes.Buffer
	log := New(Local, WithOutput(&buf))

	log.Debug("debug message")
	log.Info("info message")
	log.Error("error message")

	output := buf.String()
	assert.Contains(t, output, "debug message", "local should emit debug logs")
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "error message")
	// Text format (not JSON)
	assert.NotContains(t, output, `"msg"`, "local should use text format, not JSON")
}

func TestNew_Staging(t *testing.T) {
	var buf bytes.Buffer
	log := New(Staging, WithOutput(&buf))

	log.Debug("debug message")
	log.Info("info message")

	output := buf.String()
	assert.NotContains(t, output, "debug message", "staging should not emit debug logs")
	assert.Contains(t, output, "info message")

	// JSON format
	lines := strings.Split(strings.TrimSpace(output), "\n")
	require.Len(t, lines, 1)
	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	assert.Equal(t, "info message", entry["msg"])
}

func TestNew_Production(t *testing.T) {
	var buf bytes.Buffer
	log := New(Production, WithOutput(&buf))

	log.Debug("debug message")
	log.Info("info message")
	log.Warn("warn message")
	log.Error("error message")

	output := buf.String()
	assert.NotContains(t, output, "debug message", "production should not emit debug logs")
	assert.NotContains(t, output, "info message", "production should not emit info logs")
	assert.NotContains(t, output, "warn message", "production should not emit warn logs")
	assert.Contains(t, output, "error message", "production should emit error logs")

	// JSON format
	lines := strings.Split(strings.TrimSpace(output), "\n")
	require.Len(t, lines, 1)
	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	assert.Equal(t, "error message", entry["msg"])
}

func TestNew_WithLevelOverride(t *testing.T) {
	var buf bytes.Buffer
	log := New(Production, WithOutput(&buf), WithLevel(slog.LevelDebug))

	log.Debug("debug in prod")

	assert.Contains(t, buf.String(), "debug in prod", "level override should take effect")
}

func TestNew_WithTraceExtractor(t *testing.T) {
	var buf bytes.Buffer
	extractor := func(ctx context.Context) []slog.Attr {
		return []slog.Attr{
			slog.String("trace_id", "abc123"),
			slog.String("span_id", "def456"),
		}
	}

	log := New(Staging, WithOutput(&buf), WithTraceExtractor(extractor))
	log.InfoContext(context.Background(), "traced message")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "abc123", entry["trace_id"])
	assert.Equal(t, "def456", entry["span_id"])
	assert.Equal(t, "traced message", entry["msg"])
}

func TestNew_ProductionWithTraceExtractor(t *testing.T) {
	var buf bytes.Buffer
	extractor := func(ctx context.Context) []slog.Attr {
		return []slog.Attr{
			slog.String("trace_id", "prod-trace"),
		}
	}

	log := New(Production, WithOutput(&buf), WithTraceExtractor(extractor))
	log.ErrorContext(context.Background(), "production error")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "prod-trace", entry["trace_id"])
}

func TestNew_UnknownEnvironment(t *testing.T) {
	var buf bytes.Buffer
	log := New(Environment("unknown"), WithOutput(&buf))

	log.Info("info message")

	// Should default to info level, JSON format
	assert.Contains(t, buf.String(), "info message")
}

func TestTraceHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	extractor := func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "t1")}
	}

	log := New(Staging, WithOutput(&buf), WithTraceExtractor(extractor))
	child := log.With("component", "auth")
	child.InfoContext(context.Background(), "with attrs")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "t1", entry["trace_id"])
	assert.Equal(t, "auth", entry["component"])
}

func TestTraceHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	extractor := func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "t2")}
	}

	log := New(Staging, WithOutput(&buf), WithTraceExtractor(extractor))
	child := log.WithGroup("request")
	child.InfoContext(context.Background(), "grouped", "method", "GET")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "grouped", entry["msg"])
	// Verify "request" group contains the method field
	reqGroup, ok := entry["request"].(map[string]any)
	require.True(t, ok, "expected 'request' group in output")
	assert.Equal(t, "GET", reqGroup["method"])
}

func TestTraceHandler_NilExtractor(t *testing.T) {
	// Even though traceHandler is created, nil extractor should not crash
	h := &traceHandler{
		inner:     slog.NewJSONHandler(&bytes.Buffer{}, nil),
		extractor: nil,
	}

	// Should not panic on Enabled or Handle
	assert.True(t, h.Enabled(context.Background(), slog.LevelInfo))

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	err := h.Handle(context.Background(), record)
	assert.NoError(t, err)
}

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		env      Environment
		expected slog.Level
	}{
		{Local, slog.LevelDebug},
		{Staging, slog.LevelInfo},
		{Production, slog.LevelError},
		{Environment("other"), slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.env), func(t *testing.T) {
			cfg := defaultConfig(tt.env)
			assert.Equal(t, tt.expected, cfg.level)
		})
	}
}
