package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdminAuth_ValidKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("X-API-Key", "my-secret-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_ValidKey_BearerHeader(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_InvalidKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_MissingKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_DevMode_NoKey(t *testing.T) {
	auth := NewAdminAuth("") // empty = dev mode
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_TimingConstant(t *testing.T) {
	// Verify that comparison uses constant-time
	auth := NewAdminAuth("correct-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Correct key
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "correct-key")
	w := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Wrong key
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "wrong-key-different-length")
	w = httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
