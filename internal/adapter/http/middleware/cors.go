package middleware

import (
	"net/http"
	"strings"
)

// CORS is middleware that adds Cross-Origin Resource Sharing headers.
type CORS struct {
	allowedOrigins map[string]bool
	allowAll       bool
}

// NewCORS creates a new CORS middleware.
// origins is a comma-separated list of allowed origins, or "*" for all.
func NewCORS(origins string) *CORS {
	if origins == "*" || origins == "" {
		return &CORS{allowAll: true}
	}

	allowed := make(map[string]bool)
	for _, o := range strings.Split(origins, ",") {
		trimmed := strings.TrimSpace(o)
		if trimmed != "" {
			allowed[trimmed] = true
		}
	}
	return &CORS{allowedOrigins: allowed}
}

// Middleware wraps an http.Handler with CORS headers.
func (c *CORS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if c.allowAll {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin != "" && c.allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Subject, X-Session-Token")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
