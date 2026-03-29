package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
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

func TestHTTPOAuthClient_DecodeIDToken_RSA(t *testing.T) {
	// Generate an RSA key pair for signing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Build a JWT
	header := map[string]string{"alg": "RS256", "kid": "test-key-1"}
	payload := map[string]any{
		"sub":            "user-123",
		"email":          "test@example.com",
		"email_verified": true,
		"name":           "Test User",
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h.Sum(nil))
	require.NoError(t, err)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwt := signingInput + "." + sigB64

	// Serve JWKS
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nB64 := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
		eBytes := big.NewInt(int64(rsaKey.E)).Bytes()
		eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

		jwks := map[string]any{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": "test-key-1",
					"alg": "RS256",
					"use": "sig",
					"n":   nB64,
					"e":   eB64,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	defer jwksServer.Close()

	client := NewHTTPOAuthClient()
	info, err := client.DecodeIDToken(context.Background(), jwt, jwksServer.URL)

	require.NoError(t, err)
	assert.Equal(t, "user-123", info.Subject)
	assert.Equal(t, "test@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Equal(t, "Test User", info.Name)
}

func TestHTTPOAuthClient_DecodeIDToken_EC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	header := map[string]string{"alg": "ES256", "kid": "ec-key-1"}
	payload := map[string]any{"sub": "ec-user", "email": "ec@example.com"}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash[:])
	require.NoError(t, err)
	rBytes := padToSize(r.Bytes(), 32)
	sBytes := padToSize(s.Bytes(), 32)
	sigB64 := base64.RawURLEncoding.EncodeToString(append(rBytes, sBytes...))
	jwt := signingInput + "." + sigB64

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		xB64 := base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes())
		yB64 := base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes())

		jwks := map[string]any{
			"keys": []map[string]string{
				{"kty": "EC", "kid": "ec-key-1", "crv": "P-256", "x": xB64, "y": yB64},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	defer jwksServer.Close()

	client := NewHTTPOAuthClient()
	info, err := client.DecodeIDToken(context.Background(), jwt, jwksServer.URL)

	require.NoError(t, err)
	assert.Equal(t, "ec-user", info.Subject)
	assert.Equal(t, "ec@example.com", info.Email)
}

func TestHTTPOAuthClient_DecodeIDToken_InvalidJWT(t *testing.T) {
	client := NewHTTPOAuthClient()
	_, err := client.DecodeIDToken(context.Background(), "not-a-jwt", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JWT format")
}

func TestHTTPOAuthClient_ExchangeCodeWithConfig_NoApple(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at-123"}) //nolint:errcheck
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	resp, err := client.ExchangeCodeWithConfig(context.Background(), server.URL, "code", "redirect", "cid", "secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "at-123", resp.AccessToken)
}

func TestHTTPOAuthClient_DecodeIDToken_NoJWKS(t *testing.T) {
	// Without JWKS URI, should still decode claims (no signature verification)
	header := map[string]string{"alg": "none"}
	payload := map[string]any{"sub": "user-no-sig", "email": "nosig@example.com"}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	jwt := headerB64 + "." + payloadB64 + ".fake-sig"

	client := NewHTTPOAuthClient()
	info, err := client.DecodeIDToken(context.Background(), jwt, "")
	require.NoError(t, err)
	assert.Equal(t, "user-no-sig", info.Subject)
}

func TestHTTPOAuthClient_DecodeIDToken_BadSignature(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	header := map[string]string{"alg": "RS256", "kid": "k1"}
	payload := map[string]any{"sub": "user"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Use a bad signature
	jwt := headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString([]byte("bad-sig"))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nB64 := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
		eBytes := big.NewInt(int64(rsaKey.E)).Bytes()
		eB64 := base64.RawURLEncoding.EncodeToString(eBytes)
		jwks := map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "n": nB64, "e": eB64}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	defer jwksServer.Close()

	client := NewHTTPOAuthClient()
	_, err = client.DecodeIDToken(context.Background(), jwt, jwksServer.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestHTTPOAuthClient_DecodeIDToken_NoMatchingKey(t *testing.T) {
	header := map[string]string{"alg": "RS256", "kid": "nonexistent"}
	payload := map[string]any{"sub": "user"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	jwt := headerB64 + "." + payloadB64 + ".sig"

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwks := map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "other-key"}}}
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	defer jwksServer.Close()

	client := NewHTTPOAuthClient()
	_, err := client.DecodeIDToken(context.Background(), jwt, jwksServer.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching key")
}

func TestHTTPOAuthClient_FetchUserInfo_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	_, err := client.FetchUserInfo(context.Background(), server.URL, "bad-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestHTTPOAuthClient_DecodeIDToken_BadHeader(t *testing.T) {
	client := NewHTTPOAuthClient()
	_, err := client.DecodeIDToken(context.Background(), "!!!.payload.sig", "")
	assert.Error(t, err)
}

func TestHTTPOAuthClient_DecodeIDToken_BadPayload(t *testing.T) {
	header := map[string]string{"alg": "none"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	client := NewHTTPOAuthClient()
	_, err := client.DecodeIDToken(context.Background(), headerB64+".!!!.sig", "")
	assert.Error(t, err)
}

func TestHTTPOAuthClient_FetchOIDCDiscovery_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	_, err := client.FetchOIDCDiscovery(context.Background(), server.URL)
	assert.Error(t, err)
}

func TestVerifyRSASignature_UnsupportedAlg(t *testing.T) {
	err := verifyRSASignature("input", []byte("sig"), "AAAA", "AQAB", "RS999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported RSA algorithm")
}

func TestVerifyECSignature_UnsupportedCurve(t *testing.T) {
	err := verifyECSignature("input", []byte("sig"), "AA", "AA", "P-521", "ES512")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported EC curve")
}

func TestHTTPOAuthClient_ExchangeCodeWithConfig_Apple(t *testing.T) {
	pemKey, _ := generateTestP256Key(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		// Verify the client_secret is a JWT (has 3 parts)
		secret := r.FormValue("client_secret")
		assert.Equal(t, 3, len(splitJWT(t, secret)), "Apple client_secret should be a JWT")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "apple-at"}) //nolint:errcheck
	}))
	defer server.Close()

	client := NewHTTPOAuthClient()
	extraConfig := map[string]string{
		"apple_team_id":    "TEAM123",
		"apple_key_id":     "KEY456",
		"apple_private_key": string(pemKey),
	}
	resp, err := client.ExchangeCodeWithConfig(context.Background(), server.URL, "code", "redirect", "com.example", "", extraConfig)
	require.NoError(t, err)
	assert.Equal(t, "apple-at", resp.AccessToken)
}

func TestHTTPOAuthClient_ExchangeCodeWithConfig_AppleInvalidKey(t *testing.T) {
	client := NewHTTPOAuthClient()
	extraConfig := map[string]string{
		"apple_team_id":     "TEAM",
		"apple_key_id":      "KEY",
		"apple_private_key": "not-a-key",
	}
	_, err := client.ExchangeCodeWithConfig(context.Background(), "http://unused", "code", "redirect", "cid", "", extraConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Apple client secret")
}

func TestVerifyECSignature_InvalidSigLen(t *testing.T) {
	err := verifyECSignature("input", []byte("short"), "AAAA", "AAAA", "P-256", "ES256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid EC signature length")
}

func TestPadToSize(t *testing.T) {
	// Shorter than size — should pad
	result := padToSize([]byte{1, 2}, 4)
	assert.Equal(t, []byte{0, 0, 1, 2}, result)

	// Equal to size — no change
	result = padToSize([]byte{1, 2, 3, 4}, 4)
	assert.Equal(t, []byte{1, 2, 3, 4}, result)

	// Longer than size — truncate
	result = padToSize([]byte{1, 2, 3, 4, 5}, 4)
	assert.Equal(t, []byte{1, 2, 3, 4}, result)
}
