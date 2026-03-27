package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authcore/internal/domain/identity"
)

// HTTPOAuthClient implements identity.OAuthClient using net/http.
type HTTPOAuthClient struct {
	httpClient *http.Client
}

// NewHTTPOAuthClient creates a new OAuth client with sensible timeouts.
func NewHTTPOAuthClient() *HTTPOAuthClient {
	return &HTTPOAuthClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

var _ identity.OAuthClient = (*HTTPOAuthClient)(nil)

// ExchangeCode exchanges an authorization code for tokens with the external provider.
func (c *HTTPOAuthClient) ExchangeCode(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string) (identity.OAuthTokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return identity.OAuthTokenResponse{}, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("failed to decode token response: %w", err)
	}

	return identity.OAuthTokenResponse{
		AccessToken:  tokenResp.AccessToken,
		IDToken:      tokenResp.IDToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// FetchUserInfo retrieves user profile from the provider's userinfo endpoint.
func (c *HTTPOAuthClient) FetchUserInfo(ctx context.Context, userInfoURL, accessToken string) (identity.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return identity.UserInfo{}, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return identity.UserInfo{
		Subject:       getStringField(raw, "sub", "id"),
		Email:         getStringField(raw, "email"),
		EmailVerified: getBoolField(raw, "email_verified"),
		Name:          getStringField(raw, "name"),
		Picture:       getStringField(raw, "picture", "avatar_url"),
		RawClaims:     raw,
	}, nil
}

// FetchOIDCDiscovery retrieves the OIDC discovery document.
func (c *HTTPOAuthClient) FetchOIDCDiscovery(ctx context.Context, discoveryURL string) (identity.OIDCConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return identity.OIDCConfig{}, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return identity.OIDCConfig{}, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	var config identity.OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return identity.OIDCConfig{}, fmt.Errorf("failed to decode discovery response: %w", err)
	}

	return config, nil
}

// getStringField extracts a string value from a map, trying multiple keys.
func getStringField(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if s, ok := val.(string); ok {
				return s
			}
			// GitHub returns `id` as a number
			if f, ok := val.(float64); ok {
				return fmt.Sprintf("%.0f", f)
			}
		}
	}
	return ""
}

func getBoolField(m map[string]any, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
