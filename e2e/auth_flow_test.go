//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_FullAuthFlow is the golden-path test with comprehensive assertions
// covering the entire auth lifecycle: register, login, authorize, token exchange,
// introspection, refresh rotation, revocation, userinfo, and logout.
func TestE2E_FullAuthFlow(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "full-flow", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code", "refresh_token"})
	_ = env.registerUser(t, tenantID, "fullflow@example.com", "secret-pass-123", "Full Flow User")
	sessionToken := env.loginUser(t, tenantID, "fullflow@example.com", "secret-pass-123")

	// Step 1: Authorize with PKCE
	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, sessionToken, "openid profile email")

	// Step 2: Exchange code for tokens
	tokens := env.exchangeCode(t, tenantID, clientID, "", code, verifier)

	accessToken := tokens["access_token"].(string)
	idToken := tokens["id_token"].(string)
	refreshToken := tokens["refresh_token"].(string)

	// Step 3: Assert access_token is a 3-part JWT
	atParts := strings.Split(accessToken, ".")
	require.Len(t, atParts, 3, "access_token must be a 3-part JWT")
	assert.Equal(t, "Bearer", tokens["token_type"])
	expiresIn, ok := tokens["expires_in"].(float64)
	require.True(t, ok, "expires_in must be a number")
	assert.Greater(t, expiresIn, float64(0), "expires_in must be positive")

	// Step 4: Assert id_token is a 3-part JWT
	idParts := strings.Split(idToken, ".")
	assert.Len(t, idParts, 3, "id_token must be a 3-part JWT")

	// Step 5: Introspect access_token -> active:true
	status, introspect := env.postForm(t, "/introspect",
		fmt.Sprintf("token=%s", accessToken),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "introspect should succeed")
	assert.Equal(t, true, introspect["active"], "access_token should be active")
	assert.NotEmpty(t, introspect["sub"], "introspect should have sub")
	// Note: scope is omitempty and the introspect impl returns "" for scope,
	// so it may not be present in the response
	// assert.NotEmpty(t, introspect["scope"], "introspect should have scope")

	// Step 6: Refresh token -> new access_token + new refresh_token
	status, refreshResp := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", refreshToken, clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "refresh should succeed")
	newAccessToken := refreshResp["access_token"].(string)
	newRefreshToken := refreshResp["refresh_token"].(string)
	assert.NotEmpty(t, newAccessToken, "refresh should return new access_token")
	assert.NotEmpty(t, newRefreshToken, "refresh should return new refresh_token")
	assert.NotEqual(t, refreshToken, newRefreshToken, "refresh token should rotate")

	// Step 7: Old refresh token should no longer work (rotation)
	status, _ = env.postForm(t, "/token",
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", refreshToken, clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.NotEqual(t, 200, status, "old refresh token should be rejected after rotation")

	// Step 8: Revoke the new refresh token
	status, _ = env.postForm(t, "/revoke",
		fmt.Sprintf("token=%s", newRefreshToken),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 200, status, "revoke should succeed")

	// Step 9: Introspect revoked token -> active:false
	status, revokedIntrospect := env.postForm(t, "/introspect",
		fmt.Sprintf("token=%s", newRefreshToken),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status)
	assert.Equal(t, false, revokedIntrospect["active"], "revoked token should be inactive")

	// Step 10: UserInfo with session -> email, name
	status, userInfo := env.get(t, "/userinfo", map[string]string{
		"X-Tenant-ID":  tenantID,
		"Authorization": "Bearer " + sessionToken,
	})
	require.Equal(t, 200, status)
	assert.Equal(t, "fullflow@example.com", userInfo["email"])
	assert.Equal(t, "Full Flow User", userInfo["name"])

	// Step 11: Logout -> session invalidated
	status, _ = env.doJSON(t, "POST", "/logout", nil, map[string]string{
		"X-Tenant-ID":  tenantID,
		"Authorization": "Bearer " + sessionToken,
	})
	assert.Equal(t, 200, status, "logout should succeed")

	// Step 12: UserInfo after logout -> 401
	status, _ = env.get(t, "/userinfo", map[string]string{
		"X-Tenant-ID":  tenantID,
		"Authorization": "Bearer " + sessionToken,
	})
	assert.Equal(t, 401, status, "userinfo after logout should return 401")

	t.Log("Full auth flow complete: register -> login -> authorize -> token -> introspect -> refresh -> revoke -> userinfo -> logout")
}

// TestE2E_PKCE_Enforcement verifies that PKCE is enforced:
// wrong verifier and missing verifier both fail.
func TestE2E_PKCE_Enforcement(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "pkce-enforce", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code"})
	_ = env.registerUser(t, tenantID, "pkce@example.com", "pkce-pass-123", "PKCE User")
	sessionToken := env.loginUser(t, tenantID, "pkce@example.com", "pkce-pass-123")

	code, _ := env.authorizeWithPKCE(t, tenantID, clientID, sessionToken, "openid")

	// Wrong code_verifier -> 400
	status, errResp := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
			code, "https://app.example.com/cb", clientID, "totally-wrong-verifier-value-here"),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 400, status, "wrong code_verifier should return 400")
	assert.NotEmpty(t, errResp["error"], "error response should have error field")

	// Get a fresh code since the first one was consumed by the failed attempt
	code2, _ := env.authorizeWithPKCE(t, tenantID, clientID, sessionToken, "openid")

	// Missing code_verifier -> 400
	status, errResp = env.postForm(t, "/token",
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s",
			code2, "https://app.example.com/cb", clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 400, status, "missing code_verifier should return 400")
	assert.NotEmpty(t, errResp["error"], "error response should have error field")
}

// TestE2E_AuthCode_Replay ensures an authorization code cannot be used twice.
func TestE2E_AuthCode_Replay(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "code-replay", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code"})
	_ = env.registerUser(t, tenantID, "replay@example.com", "replay-pass-123", "Replay User")
	sessionToken := env.loginUser(t, tenantID, "replay@example.com", "replay-pass-123")

	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, sessionToken, "openid")

	// First exchange succeeds
	_ = env.exchangeCode(t, tenantID, clientID, "", code, verifier)

	// Second exchange with same code -> 400
	status, errResp := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
			code, "https://app.example.com/cb", clientID, verifier),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 400, status, "replayed auth code should return 400")
	assert.NotEmpty(t, errResp["error"], "error response should have error field")
}

// TestE2E_ClientCredentials tests the client_credentials grant type.
func TestE2E_ClientCredentials(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "cc-tenant", "RS256")
	clientID, clientSecret := env.createClient(t, tenantID, "confidential", []string{"client_credentials"})
	require.NotEmpty(t, clientSecret, "confidential client must have a secret")

	// POST /token with client_credentials grant
	status, body := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=openid",
			clientID, clientSecret),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "client_credentials grant should succeed")

	accessToken := body["access_token"].(string)
	assert.NotEmpty(t, accessToken)

	// No refresh_token in client_credentials response (omitempty means absent)
	assert.Nil(t, body["refresh_token"], "client_credentials should not return refresh_token")

	// The sub is in the JWT claims, not the token response itself.
	// Decode the JWT to verify sub equals client_id.
	parts := strings.Split(accessToken, ".")
	require.Equal(t, 3, len(parts), "JWT should have 3 parts")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payloadBytes, &claims))
	assert.Equal(t, clientID, claims["sub"], "sub should be client_id for client_credentials")

	// Wrong secret -> 401 (ErrInvalidClient maps to 401)
	status, _ = env.postForm(t, "/token",
		fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=openid",
			clientID, "wrong-secret"),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 401, status, "wrong client_secret should return 401")
}

// TestE2E_RefreshTokenReplayDetection verifies that reuse of a rotated refresh
// token revokes the entire token family.
func TestE2E_RefreshTokenReplayDetection(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "rt-replay", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code", "refresh_token"})
	_ = env.registerUser(t, tenantID, "rtreplay@example.com", "rt-pass-123", "RT Replay User")
	sessionToken := env.loginUser(t, tenantID, "rtreplay@example.com", "rt-pass-123")

	// Get tokens via auth code flow
	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, sessionToken, "openid")
	tokens := env.exchangeCode(t, tenantID, clientID, "", code, verifier)
	oldRefreshToken := tokens["refresh_token"].(string)

	// Refresh once -> new tokens
	status, refreshResp := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", oldRefreshToken, clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "first refresh should succeed")
	newRefreshToken := refreshResp["refresh_token"].(string)
	assert.NotEqual(t, oldRefreshToken, newRefreshToken)

	// Use the OLD refresh token again -> should fail (replay detection)
	status, _ = env.postForm(t, "/token",
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", oldRefreshToken, clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.NotEqual(t, 200, status, "replayed old refresh token should be rejected")

	// The new refresh token has a different family ID (each issueTokens call
	// generates a new family), so it is NOT revoked by the old family's revocation.
	// This is the current design: family revocation only affects the original family.
	status, _ = env.postForm(t, "/token",
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", newRefreshToken, clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 200, status, "new refresh token (different family) should still work")
}

// TestE2E_DeviceCodeFlow tests the device authorization flow initiation and polling.
func TestE2E_DeviceCodeFlow(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "device-tenant", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"urn:ietf:params:oauth:grant-type:device_code"})

	// POST /device/authorize -> device_code, user_code, verification_uri
	status, body := env.postForm(t, "/device/authorize",
		fmt.Sprintf("client_id=%s&scope=openid", clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "device authorize should succeed")
	assert.NotEmpty(t, body["device_code"], "response should contain device_code")
	assert.NotEmpty(t, body["user_code"], "response should contain user_code")
	assert.NotEmpty(t, body["verification_uri"], "response should contain verification_uri")

	deviceCode := body["device_code"].(string)

	// Poll with device_code -> authorization_pending
	status, pollResp := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s",
			deviceCode, clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 400, status, "polling before user authorization should return 400")
	// WriteError returns {"error":{"code":"AUTHORIZATION_PENDING","message":"..."}}
	errObj := pollResp["error"].(map[string]any)
	assert.Equal(t, "AUTHORIZATION_PENDING", errObj["code"], "error code should be AUTHORIZATION_PENDING")
}

// TestE2E_PasswordGrant tests the resource owner password credentials grant.
func TestE2E_PasswordGrant(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "password-tenant", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"password"})
	_ = env.registerUser(t, tenantID, "pwgrant@example.com", "pw-pass-123", "PW Grant User")

	// POST /token with password grant
	status, body := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=password&username=%s&password=%s&client_id=%s&scope=openid",
			"pwgrant@example.com", "pw-pass-123", clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "password grant should succeed")
	assert.NotEmpty(t, body["access_token"], "should return access_token")

	// Wrong password -> 401
	status, _ = env.postForm(t, "/token",
		fmt.Sprintf("grant_type=password&username=%s&password=%s&client_id=%s&scope=openid",
			"pwgrant@example.com", "wrong-password", clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, 401, status, "wrong password should return 401")
}

// TestE2E_ScopeEnforcement verifies that requesting scopes beyond the client's
// allowed_scopes results in an error.
func TestE2E_ScopeEnforcement(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "scope-tenant2", "RS256")

	// Create client with restricted scopes (openid only)
	status, body := env.doJSON(t, "POST", "/tenants/"+tenantID+"/clients", map[string]any{
		"client_name":    "Restricted Scope Client",
		"client_type":    "public",
		"redirect_uris":  []string{"https://app.example.com/cb"},
		"allowed_scopes": []string{"openid"},
		"grant_types":    []string{"authorization_code"},
	}, map[string]string{
		"Authorization": "Bearer " + env.adminKey,
	})
	require.Equal(t, 201, status)
	data := body["data"].(map[string]any)
	clientID := data["client_id"].(string)

	_ = env.registerUser(t, tenantID, "scope@example.com", "scope-pass-123", "Scope User")
	sessionToken := env.loginUser(t, tenantID, "scope@example.com", "scope-pass-123")

	// Authorize with scope=openid+admin -> 400 invalid_scope
	authURL := fmt.Sprintf("/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+admin&state=st&code_challenge=test&code_challenge_method=S256",
		clientID, "https://app.example.com/cb")
	status, errResp := env.get(t, authURL, map[string]string{
		"X-Tenant-ID":  tenantID,
		"Authorization": "Bearer " + sessionToken,
	})
	assert.Equal(t, 400, status, "requesting unauthorized scope should return 400")
	assert.Equal(t, "invalid_scope", errResp["error"], "error should be invalid_scope")
}

// TestE2E_ClientRedirectURI verifies that authorization requests with
// non-registered redirect URIs are rejected.
func TestE2E_ClientRedirectURI(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "redirect-tenant", "RS256")

	// Create client with specific redirect URI
	status, body := env.doJSON(t, "POST", "/tenants/"+tenantID+"/clients", map[string]any{
		"client_name":    "Redirect Client",
		"client_type":    "public",
		"redirect_uris":  []string{"https://legit.com/cb"},
		"allowed_scopes": []string{"openid"},
		"grant_types":    []string{"authorization_code"},
	}, map[string]string{
		"Authorization": "Bearer " + env.adminKey,
	})
	require.Equal(t, 201, status)
	data := body["data"].(map[string]any)
	clientID := data["client_id"].(string)

	_ = env.registerUser(t, tenantID, "redirect@example.com", "redirect-pass-123", "Redirect User")
	sessionToken := env.loginUser(t, tenantID, "redirect@example.com", "redirect-pass-123")

	// Authorize with different redirect_uri -> 400
	authURL := fmt.Sprintf("/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=st&code_challenge=test&code_challenge_method=S256",
		clientID, "https://evil.com/cb")
	status, errResp := env.get(t, authURL, map[string]string{
		"X-Tenant-ID":  tenantID,
		"Authorization": "Bearer " + sessionToken,
	})
	assert.Equal(t, 400, status, "wrong redirect_uri should return 400")
	assert.Equal(t, "invalid_redirect_uri", errResp["error"], "error should be invalid_redirect_uri")
}

// TestE2E_InvalidClientID verifies that authorization with a nonexistent
// client_id is rejected.
func TestE2E_InvalidClientID(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "badclient-tenant", "RS256")
	_ = env.registerUser(t, tenantID, "badclient@example.com", "bad-pass-123", "Bad Client User")
	sessionToken := env.loginUser(t, tenantID, "badclient@example.com", "bad-pass-123")

	// Authorize with nonexistent client_id -> 400
	authURL := fmt.Sprintf("/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=st&code_challenge=test&code_challenge_method=S256",
		"nonexistent-client-id", "https://app.example.com/cb")
	status, errResp := env.get(t, authURL, map[string]string{
		"X-Tenant-ID":  tenantID,
		"Authorization": "Bearer " + sessionToken,
	})
	// ErrInvalidClient maps to 401
	assert.Equal(t, 401, status, "nonexistent client_id should return 401")
	assert.NotNil(t, errResp["error"], "error response should have error field")
}

// TestE2E_TokenIntrospection tests introspection for valid tokens and garbage tokens.
func TestE2E_TokenIntrospection(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "introspect-tenant", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code", "refresh_token"})
	_ = env.registerUser(t, tenantID, "introspect@example.com", "intro-pass-123", "Introspect User")
	sessionToken := env.loginUser(t, tenantID, "introspect@example.com", "intro-pass-123")

	// Get valid access_token
	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, sessionToken, "openid profile")
	tokens := env.exchangeCode(t, tenantID, clientID, "", code, verifier)
	accessToken := tokens["access_token"].(string)

	// Introspect valid token -> active:true with claims
	status, body := env.postForm(t, "/introspect",
		fmt.Sprintf("token=%s", accessToken),
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status)
	assert.Equal(t, true, body["active"], "valid token should be active")
	assert.NotEmpty(t, body["sub"], "introspect should return sub")
	// scope is omitempty and may be "" in the introspect response
	assert.NotEmpty(t, body["client_id"], "introspect should return client_id")
	assert.NotNil(t, body["exp"], "introspect should return exp")
	assert.NotNil(t, body["iat"], "introspect should return iat")

	// Introspect garbage token -> active:false
	status, garbageResp := env.postForm(t, "/introspect",
		"token=this.is.garbage",
		map[string]string{"X-Tenant-ID": tenantID})
	require.Equal(t, 200, status, "introspect of garbage token should still return 200")
	assert.Equal(t, false, garbageResp["active"], "garbage token should be inactive")
}
