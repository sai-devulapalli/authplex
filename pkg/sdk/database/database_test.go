package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResolveDriverName(t *testing.T) {
	tests := []struct {
		driver   Driver
		expected string
		isErr    bool
	}{
		{Postgres, "pgx", false},
		{SQLServer, "sqlserver", false},
		{Driver("unknown"), "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.driver), func(t *testing.T) {
			name, err := resolveDriverName(tt.driver)
			if tt.isErr {
				assert.NotNil(t, err)
				assert.Empty(t, name)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.expected, name)
			}
		})
	}
}

func TestDefaultConnConfig(t *testing.T) {
	cfg := defaultConnConfig()

	assert.Equal(t, 25, cfg.maxOpenConns)
	assert.Equal(t, 5, cfg.maxIdleConns)
	assert.Equal(t, 30*time.Minute, cfg.connMaxLifetime)
	assert.Equal(t, 5*time.Minute, cfg.connMaxIdleTime)
}

func TestConnOptions(t *testing.T) {
	cfg := defaultConnConfig()

	WithMaxOpenConns(50)(&cfg)
	WithMaxIdleConns(10)(&cfg)
	WithConnMaxLifetime(1 * time.Hour)(&cfg)
	WithConnMaxIdleTime(10 * time.Minute)(&cfg)

	assert.Equal(t, 50, cfg.maxOpenConns)
	assert.Equal(t, 10, cfg.maxIdleConns)
	assert.Equal(t, 1*time.Hour, cfg.connMaxLifetime)
	assert.Equal(t, 10*time.Minute, cfg.connMaxIdleTime)
}

func TestNewConnection_UnsupportedDriver(t *testing.T) {
	result := NewConnection(t.Context(), Driver("mysql"), "fake-dsn")

	assert.True(t, result.IsErr())
	assert.Contains(t, result.Error().Message, "unsupported database driver")
}

func TestNewConnection_InvalidDSN(t *testing.T) {
	// pgx driver is not registered in this test context,
	// so sql.Open will fail or ping will fail
	result := NewConnection(t.Context(), Postgres, "invalid://dsn")

	assert.True(t, result.IsErr())
}
