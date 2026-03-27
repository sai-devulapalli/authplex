package health

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	assert.NotNil(t, r)
	assert.Empty(t, r.checkers)
}

func TestRegistry_CheckAll_Empty(t *testing.T) {
	r := NewRegistry()
	status, results := r.CheckAll(context.Background())

	assert.Equal(t, StatusUp, status)
	assert.Empty(t, results)
}

func TestRegistry_CheckAll_AllUp(t *testing.T) {
	r := NewRegistry()
	r.Register("db", CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "db", Status: StatusUp}
	}))
	r.Register("cache", CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "cache", Status: StatusUp}
	}))

	status, results := r.CheckAll(context.Background())

	assert.Equal(t, StatusUp, status)
	assert.Len(t, results, 2)
}

func TestRegistry_CheckAll_OneDown(t *testing.T) {
	r := NewRegistry()
	r.Register("db", CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "db", Status: StatusUp}
	}))
	r.Register("cache", CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "cache", Status: StatusDown, Details: "connection refused"}
	}))

	status, results := r.CheckAll(context.Background())

	assert.Equal(t, StatusDown, status)
	assert.Len(t, results, 2)
}

func TestRegistry_Register_Overwrites(t *testing.T) {
	r := NewRegistry()
	r.Register("db", CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "db", Status: StatusDown}
	}))
	r.Register("db", CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "db", Status: StatusUp}
	}))

	status, results := r.CheckAll(context.Background())

	assert.Equal(t, StatusUp, status)
	assert.Len(t, results, 1)
	assert.Equal(t, StatusUp, results[0].Status)
}

func TestCheckerFunc(t *testing.T) {
	fn := CheckerFunc(func(ctx context.Context) CheckResult {
		return CheckResult{Name: "test", Status: StatusUp, Details: "ok"}
	})

	result := fn.Check(context.Background())
	assert.Equal(t, "test", result.Name)
	assert.Equal(t, StatusUp, result.Status)
	assert.Equal(t, "ok", result.Details)
}
