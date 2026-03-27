# AuthCore Roadmap & Pending Items

## Current State (as of 2026-03-27)

**Modules Complete:** 0–8 + Production Hardening
**Stats:** ~170 Go files, 596 tests, 84.1% coverage, 22 endpoints, 33 packages

---

## Pending Items by Priority

### Critical — Blocks Production Deployment

| # | Item | Effort | Description | Status |
|---|------|--------|-------------|--------|
| 1 | Remaining Postgres repo implementations | Medium | `setupPostgresRepos()` has TODOs — only JWK + tenant repos are real Postgres. Need: client, user, session, refresh, provider, external identity, TOTP | Migration SQL exists, repos need writing |
| 2 | Redis for ephemeral stores | Medium | Auth codes, device codes, blacklist, state, sessions, MFA challenges should use Redis with TTL | In-memory works, not scalable |
| 3 | Scope validation enforcement | Small | Scopes stored on client but never checked during token issuance | Domain exists |
| 4 | MFA enforcement in /authorize | Small | `CreateChallenge` service exists, /authorize handler doesn't call it | Service exists |
| 5 | E2E tests | Medium | Golden path: register → login → authorize → token → verify JWT via /jwks | Test infra exists |

### High — Production Quality

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 6 | Rate limiting | Medium | `/login`, `/mfa/verify`, `/token` need brute-force protection |
| 7 | Encryption at rest | Medium | TOTP secrets, provider client_secrets stored plaintext in DB |
| 8 | Email service | Medium | Verification emails, password reset tokens |
| 9 | Password reset flow | Medium | Forgot → token → reset |
| 10 | SAML 2.0 | Large | Enterprise SSO — see [SAML analysis](#saml-20-analysis) below |

### Medium — Feature Parity

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 11 | WebAuthn/FIDO2 (Module 7b) | Large | Hardware key / biometric MFA |
| 12 | ID token from social login | Small | Decode provider id_token (marked `// TODO`) |
| 13 | Apple JWT client_secret | Medium | ES256-signed JWT per token exchange request |
| 14 | Refresh token cleanup | Small | Expired/revoked tokens accumulate forever |
| 15 | Key auto-rotation | Small | Currently manual via API |
| 16 | OIDC /userinfo from access token | Small | Currently uses session token; should also accept JWT |
| 17 | Admin CLI tool | Small | `authcore tenant create --domain example.com` |
| 18 | CORS per-client | Small | Currently global; should be per-client whitelist |

### Low — Nice to Have

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 19 | mTLS | Medium | Machine-to-machine TLS certificate auth |
| 20 | OpenTelemetry | Medium | Logger trace hooks ready, SDK not wired |
| 21 | JWE (encrypted tokens) | Medium | RFC 7516 |
| 22 | Audit logging | Medium | Track admin actions, login events |
| 23 | LDAP integration | Medium | Direct AD bind (see [LDAP analysis](#ldap-analysis)) |
| 24 | Admin UI | Large | Separate SPA recommended (see [Admin UI analysis](#admin-ui-analysis)) |
| 25 | Security audit | External | Zero production deployments, no external review |
| 26 | Dynamic Client Registration (RFC 7591) | Medium | Clients can self-register |
| 27 | Pushed Authorization Requests (PAR) | Medium | RFC 9126 |

---

## Feature Analysis: SAML, LDAP, Admin UI

### SAML 2.0 Analysis

**Verdict: Build it.** Enterprise blocker — banks, hospitals, government require SAML.

**What it requires:**
- XML signing/verification (`encoding/xml` + `crypto/x509`)
- SAML metadata endpoint (`GET /saml/metadata`)
- SAML SSO endpoint (`GET /saml/sso` — receives AuthnRequest)
- SAML ACS endpoint (`POST /saml/acs` — receives Response/Assertion)
- Assertion builder (XML → sign → base64 → POST/redirect binding)
- SP-initiated and IdP-initiated flows
- Certificate management per tenant
- Recommended library: `github.com/crewjam/saml`

**Effort:** 3-4 weeks, ~30 new files

**Pros:**
- #1 enterprise blocker — without SAML, AuthCore is rejected by enterprise procurement
- Original spec requirement
- Competitive parity with Keycloak and Cognito
- Reuses existing tenant isolation and key management

**Cons:**
- XML complexity — canonicalization (C14N) and signature wrapping attacks
- Large attack surface (XXE, XML injection)
- SAML spec is massive with endless edge cases
- Declining protocol (new integrations prefer OIDC)
- Testing requires real SAML SPs (Salesforce, Workday)

**Recommendation:** Use `crewjam/saml` library rather than implementing from scratch. Focus on SP-initiated flow first (most common). IdP-initiated can come later.

---

### LDAP Analysis

**Verdict: Skip for now.** Generic OIDC provider covers Azure AD, which handles 90% of LDAP use cases.

**What it requires:**
- LDAP client adapter (bind, search, authenticate)
- User federation: sync LDAP users → AuthCore, or passthrough auth
- Group/role mapping from LDAP attributes
- Connection pooling, TLS/STARTTLS
- Config per tenant (LDAP URL, bind DN, search base, attribute mapping)
- Library: `github.com/go-ldap/ldap/v3`

**Effort:** 1-2 weeks

**Pros:**
- Active Directory is still #1 corporate directory
- No user migration needed — authenticate against existing LDAP
- Fits headless model (backend protocol, no UI)

**Cons:**
- Niche and shrinking — new orgs use Azure AD (OIDC), not raw LDAP
- AuthCore already supports Generic OIDC — Azure AD exposes OIDC endpoints
- LDAP connections are stateful (pooling, reconnection, timeouts)
- Every LDAP deployment has custom schema — mapping is never clean
- Security surface: LDAP injection, plaintext bind credentials

**Recommendation:** Only build on specific customer demand. For most cases, configure Azure AD as a Generic OIDC provider instead.

---

### Admin UI Analysis

**Verdict: Don't build built-in. Consider separate companion project.**

**Three options:**

| Option | Effort | Description | Fits AuthCore? |
|--------|--------|-------------|---------------|
| **A: API-only** (current) | Done | Developers use curl/Postman | Yes — headless philosophy |
| **B: Admin CLI** | 1 week | `authcore tenant create --domain example.com` | Yes — stays headless |
| **C: Separate SPA** (`authcore-admin` repo) | 2-3 weeks | React dashboard calling management API | Yes — optional companion |
| **D: Built-in UI** | 4-6 weeks | Serve HTML from same binary | **No** — breaks headless |

**Why not built-in (Option D):**
- Breaks the core "headless" design principle
- Doubles the maintenance surface (Go backend + JS frontend)
- Makes AuthCore "Keycloak but worse" — competing on UI is a losing battle
- Admin UI needs its own auth, CSRF protection, CSP headers
- AuthCore's differentiator is being lightweight; a UI adds weight

**Recommended approach:**
1. **Now:** Option B — build an admin CLI tool (small effort, high developer productivity)
2. **Later:** Option C — separate `authcore-admin` React SPA (optional, open-source)
3. **Never:** Option D — built-in UI contradicts the architecture

This mirrors IdentityServer's approach: Duende sells the admin UI as a separate product. The core server stays clean.

---

## Deployment Readiness Checklist

### For Local Development ✅
- [x] In-memory storage
- [x] All 22 endpoints functional
- [x] Register → Login → Authorize → Token → Verify JWT
- [x] Social login flow (with configured provider)
- [x] MFA TOTP enrollment and verification
- [x] Hot reload with `go run`

### For Staging Deployment 🟡
- [x] Postgres connection + auto-migrations
- [x] CORS configured
- [x] Admin API protected with API key
- [x] Client enforcement on OAuth flows
- [ ] Remaining Postgres repos (items 1-2 above)
- [ ] Redis for ephemeral stores
- [ ] Scope validation
- [ ] E2E tests passing

### For Production Deployment 🔴
- [ ] All staging items
- [ ] Rate limiting
- [ ] Encryption at rest
- [ ] Email verification
- [ ] Password reset
- [ ] Security audit
- [ ] Load testing
- [ ] Monitoring (metrics, alerts)
- [ ] Backup/restore procedures
- [ ] Incident response playbook

---

## Implementation Priority (Recommended Order)

| Phase | Items | Gets you to |
|-------|-------|-------------|
| **Phase 1** (1 week) | Items 1-2: Postgres repos + Redis | Full persistence, horizontally scalable |
| **Phase 2** (2-3 days) | Items 3-5: Scope, MFA enforcement, E2E tests | Feature-complete and tested |
| **Phase 3** (1 week) | Items 6-9: Rate limiting, encryption, email, password reset | Production-grade security |
| **Phase 4** (3-4 weeks) | Item 10: SAML 2.0 | Enterprise-ready |
| **Phase 5** (2 weeks) | Items 11, 17: WebAuthn, Admin CLI | Feature parity |
