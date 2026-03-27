# AuthCore — SDK Guide

## Overview

AuthCore can run as a **standalone server** (HTTP API) or as an **embedded Go SDK** (library). The SDK exposes the same business logic as the server but without the HTTP layer — direct Go function calls, zero network overhead.

```
Server Mode:    Your Code → HTTP → JSON → AuthCore Server → Postgres/Redis
SDK Mode:       Your Code → authcore.Login() → Postgres/Redis (direct)
```

---

## SDK vs Server

| | **Server (HTTP API)** | **SDK (Go library)** |
|--|:---:|:---:|
| Deployment | Separate process/container | Embedded in your app |
| Call overhead | HTTP + JSON serialization (~1-50ms) | Function call (~microseconds) |
| Language | Any (HTTP is universal) | Go only |
| Scaling | Independent | Scales with your app |
| Updates | Redeploy AuthCore | Recompile your app |

---

## Three Persistence Options

### Option 1: Shared Database

SDK uses **your existing** Postgres + Redis. No extra infrastructure.

```
┌───────────────────────────────────────────┐
│           Your Application                 │
│                                             │
│  ┌────────────┐    ┌─────────────────┐    │
│  │ Your Code  │    │ AuthCore SDK    │    │
│  │            │    │                 │    │
│  │ db.Query() │    │ auth.Login()    │    │
│  └─────┬──────┘    └───────┬─────────┘    │
│        │                    │               │
│        └──────────┬─────────┘               │
│                   ▼                          │
│     ┌───────────────────────┐               │
│     │   SAME Postgres DB     │               │
│     │                        │               │
│     │  orders        ← yours │               │
│     │  products      ← yours │               │
│     │  ───────────────────── │               │
│     │  users         ← SDK  │               │
│     │  tenants       ← SDK  │               │
│     │  clients       ← SDK  │               │
│     │  jwk_pairs     ← SDK  │               │
│     │  refresh_tokens← SDK  │               │
│     └───────────────────────┘               │
│                                              │
│     ┌───────────────────────┐               │
│     │   SAME Redis           │               │
│     │                        │               │
│     │  cart:123      ← yours │               │
│     │  cache:prod    ← yours │               │
│     │  ───────────────────── │               │
│     │  session:abc   ← SDK  │  (prefixed)   │
│     │  authcode:xyz  ← SDK  │               │
│     │  otp:t1:email  ← SDK  │               │
│     └───────────────────────┘               │
└─────────────────────────────────────────────┘
```

```go
// Pass YOUR existing connections
db, _ := sql.Open("pgx", "postgres://your-db:5432/myapp")
rdb := redis.NewClient(&redis.Options{Addr: "your-redis:6379"})

auth := authcore.New(authcore.Config{
    Issuer: "https://myapp.com",
}, db, rdb)

// SDK auto-runs migrations — creates authcore tables alongside yours
// SDK uses key prefixes in Redis — no collision with your keys
```

**Best for**: Startups, simple apps, don't want to manage separate databases.

---

### Option 2: Separate Database

SDK connects to **dedicated** Postgres + Redis. Full data isolation.

```
┌───────────────────────────────────────────┐
│           Your Application                 │
│                                             │
│  ┌────────────┐    ┌─────────────────┐    │
│  │ Your Code  │    │ AuthCore SDK    │    │
│  └─────┬──────┘    └───────┬─────────┘    │
│        │                    │               │
└────────┼────────────────────┼───────────────┘
         │                    │
         ▼                    ▼
 ┌──────────────┐    ┌──────────────┐
 │ Your Postgres │    │ Auth Postgres │
 │ (orders, etc) │    │ (users, keys) │
 └──────────────┘    └──────────────┘
 ┌──────────────┐    ┌──────────────┐
 │ Your Redis    │    │ Auth Redis    │
 │ (cache, etc)  │    │ (sessions)   │
 └──────────────┘    └──────────────┘
```

```go
// Separate connections
appDB, _ := sql.Open("pgx", "postgres://app-db:5432/myapp")
authDB, _ := sql.Open("pgx", "postgres://auth-db:5432/authcore")
authRedis := redis.NewClient(&redis.Options{Addr: "auth-redis:6379"})

// Your app uses appDB, SDK uses authDB
auth := authcore.New(config, authDB, authRedis)
```

**Best for**: Security-sensitive apps, compliance (SOC2/HIPAA), multi-service architectures.

---

### Option 3: Embedded (No External Database)

SDK uses **in-memory storage**. Zero infrastructure.

```
┌──────────────────────────────────┐
│       Your Application            │
│                                    │
│  ┌───────────────────────────┐   │
│  │ AuthCore SDK               │   │
│  │                             │   │
│  │  ┌──────────┐ ┌──────────┐│   │
│  │  │ In-Memory│ │ In-Memory││   │
│  │  │ (users)  │ │(sessions)││   │
│  │  └──────────┘ └──────────┘│   │
│  └───────────────────────────┘   │
│                                    │
│  No Postgres. No Redis.            │
│  Data lost on restart.             │
└──────────────────────────────────┘
```

```go
// No database needed — pass nil
auth := authcore.New(config, nil, nil)
```

**Best for**: Development, testing, CLI tools, prototyping.

---

## How the SDK Decides What to Use

```go
func New(cfg Config, db *sql.DB, rdb *redis.Client) *AuthCore {

    // Scenario 1: Full persistence (Postgres + Redis)
    if db != nil && rdb != nil {
        userRepo      = postgres.NewUserRepository(db)
        tenantRepo    = postgres.NewTenantRepository(db)
        clientRepo    = postgres.NewClientRepository(db)
        jwkRepo       = postgres.NewJWKRepository(db)
        refreshRepo   = postgres.NewRefreshTokenRepository(db)
        sessionRepo   = redis.NewSessionRepository(rdb)
        codeRepo      = redis.NewCodeRepository(rdb)
        otpRepo       = redis.NewOTPRepository(rdb)
        blacklist     = redis.NewTokenBlacklist(rdb)
        // Auto-run migrations
        postgres.RunMigrations(ctx, db)
    }

    // Scenario 2: Postgres only (no Redis)
    if db != nil && rdb == nil {
        userRepo      = postgres.NewUserRepository(db)
        // ... other Postgres repos ...
        sessionRepo   = cache.NewInMemorySessionRepository()    // fallback
        codeRepo      = cache.NewInMemoryCodeRepository()       // fallback
        otpRepo       = cache.NewInMemoryOTPRepository()        // fallback
    }

    // Scenario 3: Everything in-memory (dev mode)
    if db == nil {
        userRepo      = cache.NewInMemoryUserRepository()
        tenantRepo    = cache.NewInMemoryTenantRepository()
        sessionRepo   = cache.NewInMemorySessionRepository()
        // ... all in-memory ...
    }

    // Wire application services (IDENTICAL to server mode)
    return &AuthCore{
        User:   user.NewService(userRepo, sessionRepo, hasher, logger),
        Auth:   auth.NewService(codeRepo, jwksSvc, signer, logger),
        Client: client.NewService(clientRepo, hasher, logger),
        // ...
    }
}
```

**The application logic is identical across all three options.** Only the storage adapters change — this is the hexagonal architecture at work.

---

## SDK Usage Examples

### Basic: Register + Login + JWT

```go
package main

import (
    "context"
    "database/sql"
    "fmt"
    "time"

    "github.com/sai-devulapalli/authCore/pkg/authcore"
    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/redis/go-redis/v9"
)

func main() {
    ctx := context.Background()

    // Connect to databases
    db, _ := sql.Open("pgx", "postgres://localhost:5432/myapp")
    rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

    // Initialize SDK
    auth := authcore.New(authcore.Config{
        Issuer:        "https://myapp.com",
        SessionTTL:    24 * time.Hour,
        AccessTTL:     1 * time.Hour,
        EncryptionKey: "your-hex-key",
    }, db, rdb)

    // Create tenant
    tenant, _ := auth.Tenant.Create(ctx, "my-tenant", "myapp.com", "https://myapp.com", "RS256")

    // Register user
    user, _ := auth.User.Register(ctx, authcore.RegisterRequest{
        Email:    "user@example.com",
        Password: "secret123",
        Name:     "User",
        TenantID: "my-tenant",
    })
    fmt.Printf("User: %s\n", user.ID)

    // Login
    session, _ := auth.User.Login(ctx, authcore.LoginRequest{
        Email:    "user@example.com",
        Password: "secret123",
        TenantID: "my-tenant",
    })
    fmt.Printf("Session: %s\n", session.Token)

    // Issue JWT tokens
    tokens, _ := auth.Auth.IssueTokens(ctx, user.ID, "my-client", "my-tenant", "openid profile")
    fmt.Printf("Access Token: %s\n", tokens.AccessToken[:50])

    // Verify JWT (local — no network call)
    claims, _ := auth.Auth.VerifyJWT(tokens.AccessToken)
    fmt.Printf("Subject: %s\n", claims.Subject)
}
```

### Middleware: Protect Your HTTP Endpoints

```go
package main

import (
    "net/http"
    "github.com/sai-devulapalli/authCore/pkg/authcore"
)

func main() {
    auth := authcore.New(config, db, rdb)

    mux := http.NewServeMux()

    // Public endpoints
    mux.HandleFunc("/", homeHandler)

    // Protected endpoints — JWT verified automatically
    mux.Handle("/api/", auth.RequireJWT(http.HandlerFunc(apiHandler)))

    // Access claims in handler
    mux.Handle("/api/me", auth.RequireJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := authcore.ClaimsFromContext(r.Context())
        fmt.Fprintf(w, "Hello %s", claims.Subject)
    })))

    http.ListenAndServe(":3000", mux)
}
```

### Mount Full OIDC Endpoints

```go
// SDK can also expose HTTP endpoints — same as server mode
auth := authcore.New(config, db, rdb)

mux := http.NewServeMux()

// Mount all OIDC/OAuth endpoints on your router
auth.MountRoutes(mux, authcore.RouteConfig{
    TenantMode:  "header",
    CORSOrigins: "*",
    AdminAPIKey: "your-key",
    RateLimit:   20,
})

// Now your app has:
// /.well-known/openid-configuration
// /jwks
// /authorize
// /token
// /register
// /login
// /otp/request
// /otp/verify
// etc.

// PLUS your own endpoints
mux.HandleFunc("/api/orders", ordersHandler)

http.ListenAndServe(":8080", mux)
```

### OTP Login (Passwordless)

```go
// Request OTP
auth.User.RequestOTP(ctx, authcore.OTPRequest{
    Email:    "user@example.com",
    Purpose:  "login",
    TenantID: "my-tenant",
})
// → OTP sent via email (SMTP) or logged to console (dev)

// Verify OTP → get session
session, _ := auth.User.VerifyOTP(ctx, authcore.OTPVerifyRequest{
    Email:    "user@example.com",
    Code:     "123456",
    TenantID: "my-tenant",
})
// → Session token returned, email marked as verified
```

### MFA (TOTP)

```go
// Enroll
enrollment, _ := auth.MFA.EnrollTOTP(ctx, "user-id", "my-tenant")
// → enrollment.Secret = "JBSWY3DPEHPK3PXP"
// → enrollment.OTPAuthURI = "otpauth://totp/..." (for QR code)

// Confirm (user scans QR, enters first code)
auth.MFA.ConfirmTOTP(ctx, "user-id", "my-tenant", "123456")

// Verify during login (when MFA is required)
auth.MFA.VerifyMFA(ctx, challengeID, "totp", "654321")
```

### Social Login

```go
// Configure provider
auth.Provider.Create(ctx, authcore.ProviderRequest{
    ProviderType: "google",
    ClientID:     "GOOGLE_CLIENT_ID",
    ClientSecret: "GOOGLE_SECRET",
    Scopes:       []string{"openid", "email", "profile"},
    TenantID:     "my-tenant",
})

// Get redirect URL for user
redirectURL, _ := auth.Social.AuthorizeRedirect(ctx, authcore.SocialRequest{
    Provider:  "google",
    ClientID:  "my-app",
    TenantID:  "my-tenant",
    // ...
})
// → Redirect user to Google

// Handle callback (after Google redirects back)
authCode, _ := auth.Social.HandleCallback(ctx, code, state)
// → AuthCore exchanges code with Google, links identity, returns auth code
```

---

## SDK Data Flow

### Server Mode (current)

```
Browser → HTTP → JSON → Handler → Service → Domain → Adapter → Postgres
                  ▲                                              │
                  └──────────── JSON ← Handler ← Service ◄──────┘

7 layers. 2 serialization boundaries. Network hop.
```

### SDK Mode

```
Your Code → Service → Domain → Adapter → Postgres
     ▲                                     │
     └─────── Go struct ← Service ◄────────┘

4 layers. 0 serialization. No network hop.
```

---

## Comparison: All Three Persistence Options

| | Shared DB | Separate DB | Embedded (no DB) |
|--|:---------:|:-----------:|:----------------:|
| **Infrastructure** | Your existing Postgres + Redis | Dedicated Postgres + Redis | None |
| **Extra cost** | $0 | $20-50/month | $0 |
| **Data isolation** | Same DB, different tables | Fully separate | In-process |
| **Persistence** | Yes | Yes | RAM only |
| **Horizontal scaling** | Yes (shared Redis) | Yes | No (single process) |
| **Migrations** | Auto-run, creates authcore tables | Auto-run, own DB | N/A |
| **Redis key collision** | No (prefixed: `session:`, `otp:`, etc.) | No (separate instance) | N/A |
| **Best for** | Startups, simple apps | Compliance, multi-service | Dev, testing, CLI |
| **Init code** | `New(cfg, yourDB, yourRedis)` | `New(cfg, authDB, authRedis)` | `New(cfg, nil, nil)` |

---

## Database Tables Created by SDK

When you pass a Postgres connection, the SDK auto-runs 9 migrations:

| # | Table | Purpose |
|---|-------|---------|
| 1 | `jwk_pairs` | JWT signing keys (RSA/EC, per tenant) |
| 2 | `tenants` | Multi-tenant configuration |
| 3 | `clients` | OAuth client registry |
| 4 | `users` | User accounts + passwords |
| 5 | `refresh_tokens` | Refresh token storage (rotation tracking) |
| 6 | `identity_providers` | Social login provider config |
| 7 | `external_identities` | Social login identity linking |
| 8 | `totp_enrollments` + `mfa_challenges` | MFA data |
| 9 | `schema_migrations` | Migration tracking (run-once) |

All tables are prefixed with no schema conflict. They coexist safely with your application tables.

---

## Redis Key Prefixes

| Prefix | Data | TTL |
|--------|------|-----|
| `session:` | User sessions | 24 hours |
| `authcode:` | OAuth authorization codes | 10 minutes |
| `device:` | Device authorization codes | 15 minutes |
| `usercode:` | Device user code → device code index | 15 minutes |
| `blacklist:` | Revoked token JTIs | Token TTL |
| `oauthstate:` | Social login CSRF state | 10 minutes |
| `otp:` | OTP codes (email/SMS) | 5 minutes |

All prefixed — no collision with your application's Redis keys.

---

## When to Use What

| Your Situation | Persistence | Why |
|---------------|-------------|-----|
| Startup, single Go app | **Shared DB** | Simplest, zero extra infra |
| SaaS, compliance required | **Separate DB** | Auth data isolated |
| Development / testing | **Embedded** | No Docker, no setup |
| CLI tool with auth | **Embedded** | Single binary, zero deps |
| Microservices (Go) | **Separate DB** | Shared auth across services |
| Microservices (polyglot) | Use **server mode** instead | SDK is Go-only |
