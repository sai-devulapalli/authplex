package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/authcore/pkg/sdk/httputil"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// AdminAuth is middleware that protects management endpoints with an API key.
type AdminAuth struct {
	apiKey string
}

// NewAdminAuth creates a new AdminAuth middleware.
// If apiKey is empty, all requests are allowed (development mode).
func NewAdminAuth(apiKey string) *AdminAuth {
	return &AdminAuth{apiKey: apiKey}
}

// Middleware returns an http.Handler that checks for a valid API key.
func (a *AdminAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no API key is configured (development mode)
		if a.apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		key := extractAPIKey(r)
		if key == "" {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "API key required")) //nolint:errcheck
			return
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(a.apiKey)) != 1 {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "invalid API key")) //nolint:errcheck
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractAPIKey gets the API key from Authorization: Bearer or X-API-Key header.
func extractAPIKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}
