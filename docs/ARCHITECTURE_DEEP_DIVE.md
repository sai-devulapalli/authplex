# AuthCore vs Keycloak vs IdentityServer vs Cognito — Architecture Deep Dive

> A detailed analysis of internals, feature trade-offs, and when each wins or loses.

---

## 1. Architectural Philosophy

### AuthCore — Hexagonal, Headless, Go

```
Design: Ports & Adapters (hexagonal)
Language: Go 1.25
Binary: Single static binary, ~15MB Docker image
State: Stateless HTTP server + external Postgres/Redis
UI: None — pure API. You build the frontend.
```

**Core principle:** The domain layer has zero dependencies on HTTP, databases, or any infrastructure. Business logic is framework-free Go code. Adapters (Postgres, Redis, HTTP handlers) are interchangeable.

**Pros:**
- Tiny footprint — runs on a Raspberry Pi, perfect as K8s sidecar
- Every line is auditable — ~249 Go files, no generated code, no magic
- 83.4% test coverage + 131 E2E tests — confidence in correctness
- Embeddable — the Go SDK runs AuthCore as a library, zero network hop
- Multi-tenant by design — tenant_id on every table, not bolted on
- Fast compilation — full build in ~5 seconds

**Cons:**
- No production deployments yet — zero battle scars
- No security audit — untested against real attackers
- Headless means YOU build every UI screen
- Go-only for the embedded SDK — other languages need HTTP
- Small community (single developer) — no ecosystem of plugins

---

### Keycloak — Full-Stack, Java, Batteries Included

```
Design: Monolithic + SPI plugin system
Language: Java (Quarkus since v20, formerly WildFly)
Binary: ~500MB Docker image, requires JVM
State: Infinispan cache (distributed) + database
UI: Full admin console + themed login pages
```

**Core principle:** Everything out of the box. Login pages, admin console, user federation, protocol support, themes — all built in. Extend via Java SPI plugins.

**Pros:**
- Production-proven — 10+ years, thousands of deployments, CNCF incubating
- SAML 2.0 + LDAP + Kerberos — enterprise-ready day one
- Beautiful admin console — manage everything via UI
- Extensive SPI system — Java plugins for custom authenticators, user storage, protocol mappers
- Active security team — CVEs are found and fixed quickly
- Realm export/import — easy backup and migration
- Infinispan clustering — built-in distributed caching

**Cons:**
- Heavy — 512MB-2GB RAM typical. JVM startup time 10-30 seconds
- Complex clustering — Infinispan configuration is notoriously difficult
- Realm overhead — each tenant (realm) duplicates significant config in memory
- Theme engine limitations — FreeMarker templates are powerful but complex
- Upgrade pain — major version upgrades often break custom SPIs and themes
- No embedded mode — always a separate server
- Java skills required for any customization

---

### IdentityServer (Duende) — .NET Library, Embedded

```
Design: Library/middleware in your ASP.NET app
Language: C# (.NET 6+)
Binary: NuGet package, runs inside your app
State: Your app's database (via EF Core)
UI: None built-in (you build Razor Pages)
```

**Core principle:** Auth IS your application. Not a separate service — a library inside your .NET app. You own the data layer, the UI, and the token pipeline.

**Pros:**
- Deep .NET integration — DI, middleware, EF Core, Razor Pages all native
- Full control of the data layer — use your existing database
- Customizable token pipeline — `IProfileService`, `IResourceOwnerPasswordValidator`
- No separate deployment — auth is part of your app
- Protocol-correct — originally written by the OAuth spec implementors

**Cons:**
- **.NET only** — if you're not a .NET shop, it's irrelevant
- **Commercial license** — $1,500/yr starter, $12,000/yr enterprise. Free for dev/OSS only
- **No admin API** — no built-in management endpoints. You build everything
- **No admin UI** — Duende sells one separately
- **No user management** — bring your own user store, registration, login
- **No MFA** — bring your own
- **No social login** — you wire up `IAuthenticationHandler` yourself
- Single-language lock-in — can't use from Java, Python, Go

---

### AWS Cognito — Managed SaaS, Zero Infrastructure

```
Design: Fully managed AWS service
Language: N/A (black box)
Binary: N/A (SaaS)
State: DynamoDB (managed by AWS)
UI: Hosted UI (customizable CSS) or your own
```

**Core principle:** Zero infrastructure management. AWS handles servers, scaling, patching, security. You configure via Console/SDK and call APIs.

**Pros:**
- Zero ops — no servers, no databases, no patches
- SOC2/HIPAA compliant out of the box
- Free tier — 50K MAU at $0
- Lambda triggers — customize every auth step with serverless functions
- Hosted UI — working login page in minutes
- AWS integration — IAM, SES, SNS, CloudWatch all native

**Cons:**
- **Vendor lock-in** — deeply tied to AWS. Migration is painful
- **Expensive at scale** — $5,500/mo at 1M MAU, $25,500 at 10M
- **Limited customization** — Hosted UI is CSS-only, not truly custom
- **No GitHub/Microsoft social login** — only Google, Facebook, Apple, SAML
- **No token introspection** — can't introspect tokens server-side
- **No device code flow** — no IoT/TV auth
- **User Pool limits** — 1,000 pools per AWS account
- **Cold start latency** — Lambda triggers add 100-500ms on first call
- **No self-hosting** — if AWS goes down, your auth goes down

---

## 2. Feature-by-Feature Deep Dive

### 2.1 OAuth 2.0 / OIDC Protocol Layer

| Capability | AuthCore | Keycloak | IdentityServer | Cognito | Notes |
|-----------|----------|----------|----------------|---------|-------|
| Auth Code + PKCE | Full | Full | Full | Full | Table stakes |
| Client Credentials | Full | Full | Full | Full | M2M auth |
| Refresh Token Rotation | Family tracking + replay detection | Yes | Yes | Yes | AuthCore's replay detection revokes entire family |
| Device Code (RFC 8628) | Full | Full | Add-on | **No** | IoT/TV apps need this |
| Token Introspection | Full | Full | Full | **No** | Cognito forces local JWT validation only |
| Token Revocation | JTI blacklist + refresh revoke | Full | Full | API only | AuthCore has both access + refresh revocation |
| SAML 2.0 | **No** | Full IdP + SP | Add-on | SP only | AuthCore's biggest gap for enterprise |
| PAR | **No** | Yes | Yes | **No** | Pushed Authorization Requests (security improvement) |
| CIBA | **No** | Yes | **No** | **No** | Backchannel auth (rare use case) |

**Winner:** Keycloak (most complete). AuthCore is close but missing SAML.

**AuthCore's edge:** Refresh token replay detection with family-wide revocation — if a rotated token is reused, the entire chain is invalidated. This prevents token theft attacks.

---

### 2.2 Multi-Factor Authentication

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| TOTP (authenticator apps) | RFC 6238, ±1 window drift | Full | Custom | Full |
| WebAuthn/FIDO2 | go-webauthn library, 4 endpoints | Full | Custom | **No** |
| SMS OTP | Twilio + console sender | SPI-based | **No** | SNS |
| Email OTP | SMTP + console sender | Built-in | **No** | SES |
| Recovery Codes | **No** | Yes | **No** | **No** |
| Per-tenant MFA policy | required/optional/none per tenant | Per-realm | Custom | Per-pool |
| MFA challenge in /authorize | Intercepts auth flow, returns challenge | Seamless (built into login page) | Custom | Managed |
| Adaptive MFA | **Roadmap** | Via extensions | **No** | Advanced Security ($0.05/MAU) |

**Winner:** Keycloak (most options). AuthCore is strong with TOTP + WebAuthn + OTP.

**AuthCore's edge:** MFA is API-driven. The `/authorize` endpoint returns a challenge JSON when MFA is required — your frontend handles the UX. No redirect to a separate MFA page. No iframes.

**AuthCore's gap:** No recovery codes (users locked out if they lose authenticator). No adaptive MFA (risk-based — on roadmap).

---

### 2.3 Multi-Tenancy

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Model | tenant_id column, same DB | Realm = separate config | Manual | User Pool = separate entity |
| Max tenants | Thousands (single DB query) | Hundreds (JVM memory per realm) | Depends | 1,000 per account |
| Tenant creation | API call (<1ms) | API/UI (seconds, memory allocation) | Code change | API call |
| Per-tenant keys | Automatic (RSA/EC, auto-rotation) | Automatic | Manual | Managed |
| Per-tenant MFA | Yes | Yes | Manual | Yes |
| Per-tenant providers | Yes | Yes | Manual | Yes |
| Isolation | Application-level (WHERE tenant_id=) | Full realm isolation | N/A | Full pool isolation |
| Cross-tenant SSO | **No** | Yes (realm-to-realm) | Manual | **No** |

**Winner:** AuthCore for scale (thousands of tenants, lightweight). Keycloak for features (cross-tenant SSO).

**AuthCore's edge:** Creating a tenant is a simple INSERT — no memory allocation, no config duplication. A single AuthCore instance can serve thousands of tenants because they share the same database tables, filtered by tenant_id.

**AuthCore's gap:** Application-level isolation only. DB-level RLS is on Tier 1 roadmap. No cross-tenant SSO.

---

### 2.4 User Management

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Registration | POST /register (API) | UI + API | **None** (BYO) | UI + API + Hosted |
| Login | POST /login (API) | UI + API + themes | **None** (BYO) | UI + API + Hosted |
| Password hashing | bcrypt cost 12 | pbkdf2/bcrypt/argon2 | Configurable | SRP |
| Email verification | Auto-OTP on register | Built-in link | **None** | Built-in |
| Password reset | OTP-based | Email link | **None** | Email/SMS |
| Phone support | Phone field + SMS OTP | Phone field | **None** | Phone + SNS |
| User search/list | **Not yet** (roadmap) | Full | Depends on store | API |
| Self-service profile | **No** | Full (change password, manage sessions, devices) | **None** | Limited |
| User federation | **No** | LDAP, AD, Kerberos | **None** | SAML federation |
| Import/export | **No** | JSON realm export | **None** | CSV import |

**Winner:** Keycloak (most complete). Cognito for managed simplicity.

**AuthCore's edge:** API-only registration/login means your frontend controls the entire UX. Password hashing uses bcrypt at cost 12 (strong but fast enough).

**AuthCore's gap:** No user list/search endpoint (SCIM on roadmap). No self-service account management. No LDAP federation.

---

### 2.5 Administration

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Admin UI | Separate React SPA (authcore-admin) | Beautiful built-in console | Sold separately by Duende | AWS Console |
| Admin API | REST (30+ endpoints, API key auth) | REST + Java Client + CLI | **None** | AWS SDK/CLI |
| Admin CLI | **Roadmap** | kcadm.sh (powerful) | dotnet CLI | AWS CLI |
| Admin auth | API key (JWT-based on roadmap) | Username/password + optional 2FA | N/A | IAM policies |
| Admin roles | **Roadmap** (super_admin, tenant_admin, readonly, auditor) | Fine-grained admin permissions | N/A | IAM policies |
| Audit logging | 25+ event types, query API | Admin events + login events | **No** | CloudTrail |

**Winner:** Keycloak (built-in console + CLI + fine-grained admin roles).

**AuthCore's edge:** 30+ REST management endpoints are fully functional. Separate admin UI means it can be deployed independently (CDN, Vercel). Audit logging with query API gives full visibility.

**AuthCore's gap:** API key auth is single-level (no scoping). JWT-based admin roles with tenant_admin scoping is on Tier 1 roadmap.

---

### 2.6 Security Posture

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Security audit history | **None** | 10+ years of CVE responses | Duende advisories | AWS compliance |
| Encryption at rest | AES-256-GCM | Vault integration | DPAPI/Azure KV | KMS |
| Rate limiting | Per-IP sliding window | Brute force detection + IP blocking | **No** | WAF |
| CORS | Global (per-client on roadmap) | Per-client | Per-client | Per-pool |
| Constant-time comparison | Yes (admin auth) | Yes | Yes | N/A |
| User enumeration prevention | Yes (same error for all) | Configurable | Custom | Yes |
| Token rotation | Family tracking + replay detection | Yes | Yes | Yes |
| mTLS | Client certificate verification | Full | Full | **No** |
| CSP headers | **No** (roadmap) | Yes | Custom | N/A |
| DB-level isolation | **No** (roadmap — Postgres RLS) | Realm-level | N/A | DynamoDB |

**Winner:** Cognito (compliance certifications). Keycloak (battle-tested security).

**AuthCore's risk:** No security audit means unknown vulnerabilities. Mitigated by: 83.4% test coverage, hexagonal architecture (small attack surface), stdlib crypto (no third-party JWT libraries), and open-source review.

---

### 2.7 Operational Overhead

| Metric | AuthCore | Keycloak | IdentityServer | Cognito |
|--------|----------|----------|----------------|---------|
| Docker image | 15MB | 500MB+ | N/A | N/A |
| RAM (idle) | ~50MB | ~512MB | ~200MB | N/A |
| RAM (1K concurrent) | ~150MB | ~1GB | ~400MB | N/A |
| Startup time | <1 second | 10-30 seconds | 2-5 seconds | N/A |
| Horizontal scaling | Stateless, add instances | Infinispan clustering (complex) | Depends on host | Auto |
| Database | Postgres (12 migrations) | Postgres/MySQL/Oracle (100+ migrations) | Any via EF Core | Managed |
| Config complexity | 23 env vars | Hundreds of realm settings | .NET DI config | Console clicks |
| Upgrade process | Replace binary | Re-test themes + SPIs | NuGet update | Managed |

**Winner:** AuthCore (smallest, fastest, simplest). Cognito (zero ops).

**AuthCore's edge:** A single AuthCore binary + Postgres + Redis uses ~500MB total RAM. Keycloak alone uses that much. Startup in <1 second vs 10-30 seconds for JVM warmup.

---

### 2.8 Extensibility

| Extension | AuthCore | Keycloak | IdentityServer | Cognito |
|----------|----------|----------|----------------|---------|
| Custom authenticator | Implement Go interface | Java SPI (hot-deploy) | .NET middleware | Lambda |
| Custom user store | `user.Repository` port | User Federation SPI | `IUserStore` | Lambda |
| Custom claims | Modify `Claims` struct | Protocol mappers (UI) | `IProfileService` | Lambda |
| Custom provider | `OAuthClient` interface | IdP SPI | `IAuthenticationHandler` | OIDC only |
| Plugin hot-reload | **No** (compile-time) | **Yes** (runtime JAR) | **No** (compile-time) | **Yes** (Lambda) |
| Extension language | Go only | Java only | C# only | Any (Lambda) |
| Webhooks | **Roadmap** | Admin events + SPI | **No** | Lambda triggers |

**Winner:** Keycloak (hot-deploy Java SPIs, most extension points). Cognito (any language via Lambda).

**AuthCore's trade-off:** Compile-time extensibility via Go interfaces. Safer (type-checked) but requires recompilation. No runtime plugin loading.

---

## 3. Cost at Scale

| MAU | AuthCore | Keycloak | IdentityServer | Cognito |
|-----|----------|----------|----------------|---------|
| 1K | $15/mo | $30/mo | $150/mo | $5/mo |
| 10K | $20/mo | $50/mo | $155/mo | $55/mo |
| 100K | $30/mo | $100/mo | $175/mo | $550/mo |
| 1M | $50/mo | $200/mo | $1,100/mo | $5,500/mo |
| 10M | $100/mo | $400/mo | $1,200/mo | $25,500/mo |

**Cheapest at scale:** AuthCore and Keycloak (infrastructure-only cost, no per-MAU fees).

**Most expensive:** Cognito at scale ($0.0055/MAU after 50K free tier). IdentityServer has fixed license cost regardless of scale.

---

## 4. Summary: Strengths & Weaknesses

### AuthCore

| Strength | Weakness |
|----------|----------|
| Tiny footprint (15MB, <300MB RAM) | No production track record |
| Headless — total UX control | No SAML 2.0 (roadmap) |
| Native multi-tenancy (thousands) | No security audit |
| Embeddable Go SDK | Go-only for embedded mode |
| Automatic key rotation + cleanup | No LDAP federation |
| 83% coverage + 131 E2E tests | No admin CLI (roadmap) |
| 5 language SDKs | No Prometheus metrics |

### Keycloak

| Strength | Weakness |
|----------|----------|
| Battle-tested (10+ years) | Heavy (500MB+, 512MB-2GB RAM) |
| SAML + LDAP + Kerberos | Complex clustering (Infinispan) |
| Beautiful admin console | Upgrade breakage (themes, SPIs) |
| Hot-deploy Java plugins | Realm overhead (memory per tenant) |
| CNCF incubating | 10-30 second startup |

### IdentityServer

| Strength | Weakness |
|----------|----------|
| Deep .NET integration | .NET only |
| Full token pipeline control | Commercial license ($1,500+/yr) |
| Embedded in your app | No admin API/UI |
| Protocol-correct implementation | No user management |

### Cognito

| Strength | Weakness |
|----------|----------|
| Zero ops (fully managed) | Vendor lock-in (AWS) |
| SOC2/HIPAA compliant | Expensive at scale |
| Free 50K MAU tier | Limited customization |
| Lambda extensibility | No GitHub/Microsoft social login |
| AWS ecosystem integration | No token introspection |

---

## 5. Decision Matrix

| If you need... | Choose |
|---------------|--------|
| Custom login UX, multi-tenant SaaS | **AuthCore** |
| Production-ready with SAML + LDAP now | **Keycloak** |
| Embedded auth in .NET app | **IdentityServer** |
| Zero infrastructure, AWS-native | **Cognito** |
| Smallest possible deployment | **AuthCore** (15MB) |
| Battle-tested security | **Keycloak** (10+ years) |
| Cheapest at 1M+ users | **AuthCore** or **Keycloak** |
| Compliance certifications | **Cognito** (SOC2/HIPAA) |
| WebAuthn + TOTP + OTP | **AuthCore** or **Keycloak** |
| Any-language extensibility | **Cognito** (Lambda) |
| Embeddable library mode | **AuthCore** (Go SDK) or **IdentityServer** (.NET) |
