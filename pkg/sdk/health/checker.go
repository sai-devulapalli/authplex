package health

import (
	"context"
	"sync"
)

// Status represents the health of a component.
type Status string

const (
	StatusUp   Status = "up"
	StatusDown Status = "down"
)

// CheckResult holds the outcome of a single health check.
type CheckResult struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Details string `json:"details,omitempty"`
}

// Checker is the interface for individual health checks.
type Checker interface {
	Check(ctx context.Context) CheckResult
}

// Registry aggregates multiple health checkers and evaluates them together.
type Registry struct {
	mu       sync.RWMutex
	checkers map[string]Checker
}

// NewRegistry creates a new health check registry.
func NewRegistry() *Registry {
	return &Registry{
		checkers: make(map[string]Checker),
	}
}

// Register adds a named health checker to the registry.
func (r *Registry) Register(name string, checker Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkers[name] = checker
}

// CheckAll runs all registered health checks and returns the aggregate status.
// If any check is down, the aggregate status is down.
func (r *Registry) CheckAll(ctx context.Context) (Status, []CheckResult) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make([]CheckResult, 0, len(r.checkers))
	overall := StatusUp

	for _, checker := range r.checkers {
		result := checker.Check(ctx)
		results = append(results, result)
		if result.Status == StatusDown {
			overall = StatusDown
		}
	}

	return overall, results
}

// CheckerFunc adapts a plain function to the Checker interface.
type CheckerFunc func(ctx context.Context) CheckResult

// Check implements Checker.
func (f CheckerFunc) Check(ctx context.Context) CheckResult {
	return f(ctx)
}
