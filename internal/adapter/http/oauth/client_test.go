package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPOAuthClient_ExchangeCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())
		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.Equal(t, "code-123", r.FormValue("code"))
		assert.Equal(t, "client-id", r.FormValue("client_id"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": "at-123",
			"id_token":     "idt-456",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	resp, err := client.ExchangeCode(context.Background(), server.URL, "code-123", "https://example.com/cb", "client-id", "secret")

	require.NoError(t, err)
	assert.Equal(t, "at-123", resp.AccessToken)
	assert.Equal(t, "idt-456", resp.IDToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestHTTPOAuthClient_ExchangeCode_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`)) //nolint:errcheck
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	_, err := client.ExchangeCode(context.Background(), server.URL, "bad-code", "", "cid", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

func TestHTTPOAuthClient_FetchUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer at-123", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"sub":            "user-123",
			"email":          "user@example.com",
			"email_verified": true,
			"name":           "Test User",
		})
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	info, err := client.FetchUserInfo(context.Background(), server.URL, "at-123")

	require.NoError(t, err)
	assert.Equal(t, "user-123", info.Subject)
	assert.Equal(t, "user@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Equal(t, "Test User", info.Name)
}

func TestHTTPOAuthClient_FetchUserInfo_GitHubNumericID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"id":    12345,
			"login": "octocat",
			"email": "octocat@github.com",
		})
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	info, err := client.FetchUserInfo(context.Background(), server.URL, "at-123")

	require.NoError(t, err)
	assert.Equal(t, "12345", info.Subject) // numeric ID converted to string
}

func TestHTTPOAuthClient_FetchOIDCDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"issuer":                 "https://accounts.google.com",
			"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
			"token_endpoint":         "https://oauth2.googleapis.com/token",
			"userinfo_endpoint":      "https://openidconnect.googleapis.com/v1/userinfo",
			"jwks_uri":               "https://www.googleapis.com/oauth2/v3/certs",
		})
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	config, err := client.FetchOIDCDiscovery(context.Background(), server.URL)

	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", config.Issuer)
	assert.NotEmpty(t, config.AuthorizationEndpoint)
	assert.NotEmpty(t, config.TokenEndpoint)
}

func TestGetStringField(t *testing.T) {
	m := map[string]any{"sub": "user-1", "id": float64(123)}

	assert.Equal(t, "user-1", getStringField(m, "sub"))
	assert.Equal(t, "123", getStringField(m, "id"))
	assert.Equal(t, "user-1", getStringField(m, "sub", "id"))
	assert.Equal(t, "", getStringField(m, "missing"))
}

func TestGetBoolField(t *testing.T) {
	m := map[string]any{"verified": true}

	assert.True(t, getBoolField(m, "verified"))
	assert.False(t, getBoolField(m, "missing"))
}
