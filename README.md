# AuthCore

**Headless Identity & Access Management Engine**

AuthCore is a lightweight, multi-tenant IAM engine that provides OIDC/OAuth 2.0 authentication for any tech stack. No UI — pure API. 15MB Docker image. 666 tests.

## Quick Start

```bash
make build && ./bin/authcore       # In-memory mode (development)
```

```bash
# Production (Postgres + Redis)
AUTHCORE_ENV=production \
AUTHCORE_DATABASE_DSN="postgres://..." \
AUTHCORE_REDIS_URL="redis://..." \
AUTHCORE_ADMIN_API_KEY="your-key" \
./bin/authcore
```

## What It Does

| Feature | Status |
|---------|--------|
| OIDC Discovery + JWKS | Done |
| Auth Code + PKCE | Done |
| All 5 OAuth Grant Types | Done |
| Token Revocation + Introspection | Done |
| Multi-Tenancy (header/domain) | Done |
| User Registration + Login | Done |
| Email + SMS OTP Login | Done |
| Password Reset via OTP | Done |
| Social Login (Google, GitHub, Microsoft, Apple) | Done |
| TOTP MFA with per-tenant policy | Done |
| Client Registry with enforcement | Done |
| Rate Limiting | Done |
| AES-256-GCM Encryption at Rest | Done |
| Postgres + Redis persistence | Done |

## Endpoints (25)

```
OIDC/OAuth:     /.well-known/openid-configuration  /jwks  /authorize  /token
                /device/authorize  /revoke  /introspect  /callback
User Auth:      /register  /login  /logout  /userinfo
OTP:            /otp/request  /otp/verify  /password/reset
MFA:            /mfa/totp/enroll  /mfa/totp/confirm  /mfa/verify
Management:     /tenants  /tenants/{id}  /tenants/{id}/clients  /tenants/{id}/providers
Health:         /health
```

## Architecture

```
15MB binary → Hexagonal Architecture → Postgres + Redis
```

- **Domain**: Pure Go, no I/O, no frameworks
- **Application**: Use cases orchestrating domain via port interfaces
- **Adapter**: Postgres, Redis, SMTP, Twilio, stdlib crypto (no external JWT libs)

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, layers, data flow, security model |
| [Flows](docs/FLOWS.md) | 11 sequence diagrams for all auth flows |
| [Use Cases & Integration](docs/USE_CASES.md) | SPA, mobile, M2M, device code, social login + SDK examples |
| [API Reference](docs/README.md) | Complete endpoint reference with examples |
| [Comparison](docs/COMPARISON.md) | AuthCore vs Keycloak vs IdentityServer vs Cognito |
| [Roadmap](docs/ROADMAP.md) | Pending items, SAML/LDAP/Admin UI analysis |
| [Implementation Tracker](docs/IMPLEMENTATION_TRACKER.md) | Module status, changelog, standards compliance |

## Stats

```
Files:     ~210 Go files (source + test)
Tests:     666 assertions across 38 packages
Coverage:  85.2% (85% threshold enforced)
Image:     ~15MB (distroless)
RAM:       <300MB
Deps:      6 (env, testify, x/crypto, pgx, go-redis, testcontainers)
```

## License

Private project.
