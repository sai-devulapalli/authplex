package identity

import "context"

// OAuthClient is the port interface for making OAuth 2.0 requests to external providers.
type OAuthClient interface {
	ExchangeCode(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string) (OAuthTokenResponse, error)
	FetchUserInfo(ctx context.Context, userInfoURL, accessToken string) (UserInfo, error)
	FetchOIDCDiscovery(ctx context.Context, discoveryURL string) (OIDCConfig, error)
}

// OAuthTokenResponse is the token response from an external provider.
type OAuthTokenResponse struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
}

// UserInfo is the user profile from an external provider.
type UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	RawClaims     map[string]any
}

// OIDCConfig is the discovery configuration from an OIDC provider.
type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}
