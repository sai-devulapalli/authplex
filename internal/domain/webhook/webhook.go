package webhook

import "time"

// Webhook represents a webhook endpoint registered for a tenant.
type Webhook struct {
	ID        string
	TenantID  string
	URL       string
	Secret    string   // HMAC-SHA256 signing secret
	Events    []string // e.g., ["login_success", "register", "token_revoked"]
	Enabled   bool
	CreatedAt time.Time
}
