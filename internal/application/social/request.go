package social

// SocialAuthorizeRequest contains the parameters for initiating social login.
type SocialAuthorizeRequest struct {
	Provider            string
	TenantID            string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Subject             string // X-Subject if pre-authenticated
}

// CallbackRequest contains the parameters from the provider callback.
type CallbackRequest struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}
