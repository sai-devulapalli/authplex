# PRD: Risk-Based Adaptive Authentication

> **Status:** Draft
> **Owner:** TBD
> **Last updated:** 2026-07-02
> **Related:** [ROADMAP.md §3.3](./ROADMAP.md) (Tier 3 — Differentiate)

---

## 1. Summary

Today, MFA in AuthPlex is all-or-nothing: a tenant either requires it on every login or not at all. This PRD proposes **risk-based adaptive authentication** — scoring each login attempt against a set of signals (new device, new IP, impossible travel, recent failures, off-hours access) and dynamically deciding whether to allow, step up to MFA, or block the attempt. This turns a static policy into a per-attempt decision, without requiring users who log in normally to do anything extra.

## 2. Problem Statement

- Tenants that enable MFA impose friction on every single login, including the 95%+ of logins that are the legitimate user on a known device.
- Tenants that disable MFA for UX reasons have no protection against credential stuffing, account takeover from leaked passwords, or logins from unexpected locations.
- The existing `security.Alerter` (`internal/application/security/alerter.go`) detects brute-force/credential-stuffing patterns **after the fact** (via audit event thresholds) and only logs/alerts — it never blocks or challenges the request that triggered it.
- There is no per-attempt risk signal captured today: `LoginRequest` carries only `Email`/`Password`/`TenantID` — no IP, device, or context.

## 3. Goals

- G1: Reduce MFA friction for low-risk logins while catching high-risk ones that today sail through with just a password.
- G2: Make suspicious logins (new device + new geography, impossible travel, brute-force-adjacent) trigger a step-up challenge or an outright block **before** a session is issued, not just an after-the-fact log line.
- G3: Ship as an opt-in, per-tenant, fail-open feature — zero behavior change for tenants that don't enable it, and never a hard outage risk for tenants that do.
- G4: Keep the initial scoring model transparent, deterministic, and dependency-free (rule-based), matching AuthPlex's "minimal dependencies" principle. Leave room to swap in a learned model later without changing the port contract.

## 4. Non-Goals

- Not building a full ABAC/policy engine (tracked separately, ROADMAP §3.x, Policy Engine).
- Not building bot/CAPTCHA detection or device-fingerprinting SDKs (client-side fingerprint collection is out of scope for v1 — v1 uses server-observable signals only: IP, User-Agent, timing, failure history).
- Not training or shipping an ML model in v1. The `Scorer` port is designed to allow one later, but v1 ships the deterministic rule engine only.
- Not covering the OAuth `client_credentials` / M2M / AI-agent auth path — this PRD is scoped to human login (`POST /login`, password grant, and the authorize-code browser flow). M2M risk scoring would be a separate PRD.

## 5. User Stories

- As a **tenant admin**, I want to enable adaptive MFA so my users aren't prompted for a code on every login, but still get challenged when something looks off.
- As an **end user**, logging in from my usual laptop and city, I should never see an extra step because of this feature.
- As an **end user**, logging in from a new device in a new country minutes after my last login somewhere else, I expect to be asked to verify it's me.
- As a **security engineer**, I want a real-time audit trail of risk decisions (score, signals, action taken) so I can tune thresholds and investigate incidents.
- As a **tenant admin**, I want to tune or disable risk scoring per tenant, and see it operate in "shadow mode" (score + log, never act) before enforcing it.

## 6. Signals & Scoring Model (v1)

Deterministic, additive rule engine — same values already scoped in ROADMAP §3.3:

| Signal | Weight | Description |
|--------|--------|-------------|
| New IP | +30 | Not seen for this user in the last 30 days |
| New device | +25 | User-Agent / device fingerprint not seen before |
| Impossible travel | +50 | >500km from last successful login in <1h |
| Recent failures | +20 | >3 failed attempts for this account in the last 10 min |
| Off-hours | +10 | Outside the user's typical active-hours window |
| Known IP | −20 | This IP has had >5 successful logins for this user |

Score is clamped to `[0, 100]`.

### Decision matrix

| Score | Action |
|-------|--------|
| 0–30 | Allow — no MFA |
| 31–60 | Step-up MFA required |
| 61–80 | Step-up MFA + email alert to user |
| 81–100 | Block login + admin alert |

Thresholds are per-tenant configurable (see §10), with the table above as the default.

## 7. Functional Requirements

1. Every password-based login (`user.Service.Login`) and password-grant token exchange (`auth.Service.exchangePassword`) computes a risk score before a session/token is issued.
2. Signals are computed from: request IP, User-Agent, and the user's login history (device/IP history, recent failure count from existing audit events).
3. Based on the decision matrix, the login either succeeds immediately, is held pending an MFA challenge (reusing the existing `domain/mfa.MFAChallenge` flow), or is rejected outright.
4. A block or step-up decision is recorded as a new audit event with the score and contributing signals.
5. Score ≥ 61 fires a security alert through the existing `security.AlertObserver` port (extended with a new `AlertType`).
6. Per tenant, risk scoring can be: **off** (default, current behavior), **shadow** (score + audit-log only, never blocks/challenges), or **enforced** (acts on the decision matrix).
7. If any signal source (geo-IP lookup, device history store) is unavailable or errors, the system fails open — login proceeds as if risk scoring were off — and logs the failure. Risk scoring must never be a source of login outages.
8. Admins can view recent risk decisions for their tenant (score, signals, action) via the existing audit query API — no new read API required for v1.

## 8. Architecture

Follows the existing hexagonal layering (domain → application → adapter); see the design sketch below for how it composes with current code (`domain/mfa`, `application/security.Alerter`, `application/user.Service`).

```
internal/domain/risk/
  signal.go        Signal struct — inputs to scoring (pure data)
  score.go         Score/Level types + Evaluate(Signal) Score — pure, deterministic
  repository.go    Ports: DeviceHistoryRepository, GeoIPLookup

internal/application/risk/
  service.go       Orchestrates: pulls device history + geo lookup + recent
                    failure count (via auditsvc), builds Signal, calls
                    risk.Evaluate, returns a Score + Decision

internal/adapter/risk/
  geoip/           IP → country/ASN lookup adapter
  (postgres/redis) DeviceHistoryRepository impl, reusing existing repo patterns
```

**Wiring:**
- `application/user.Service` gains `WithRiskScorer(risk.Port) *Service`, same functional-options shape as `WithAudit`/`WithOTP`.
- `LoginRequest` gains `IP` and `UserAgent` fields, populated by the HTTP handler (which already extracts `RemoteAddr` for rate limiting).
- `Login()` calls the scorer after password verification, before `sessionRepo.Create`. On `StepUp`, it creates a `domain/mfa.MFAChallenge` (same struct/flow the authorize endpoint already uses) instead of a session. On `Block`, it returns `ErrUnauthorized` and logs/alerts.
- `application/auth.Service.exchangePassword` gets the same treatment for the password grant.
- `security.Alerter` gains `AlertHighRiskLogin` in its existing `AlertType` enum — no new alerting infrastructure needed.

## 9. Data Model Changes

- New Postgres table `login_device_history` (or Redis-backed equivalent, matching the existing 10 Postgres + 7 Redis repo split): `user_id, tenant_id, device_hash, ip, country, last_seen_at, success_count`.
- `domain/audit` event enum: add `EventRiskEvaluated`, `EventStepUpRequired`, `EventLoginBlocked`.
- One new migration file (consistent with the existing 19-file auto-migration runner).

## 10. Per-Tenant Configuration

Extends the existing per-tenant settings mechanism (already covers MFA/TTL/password policy/CORS/rate limits):

```
risk_auth: {
  mode: "off" | "shadow" | "enforced",   // default "off"
  thresholds: { step_up: 31, alert: 61, block: 81 },  // defaults shown
}
```

## 11. Security & Privacy Considerations

- IP-derived geolocation is coarse (country/region, not precise location) — sufficient for "impossible travel" without storing precise user location.
- Device history storage is a hash of User-Agent + coarse client hints, not a persistent cross-site fingerprint — avoid overreach into tracking-style fingerprinting.
- Fail-open behavior (§7.7) must not become a silent bypass vector — failures are logged and, above a rate threshold, should themselves raise an operational alert (reuse `security.Alerter`).
- Risk decisions and their signals are sensitive audit data — access to them follows the same RBAC/RLS rules as existing audit log access.

## 12. Rollout Plan

1. **Phase 0 — Shadow mode only.** Ship `domain/risk` + `application/risk` + wiring, default every tenant to `mode: "off"`. Internally dogfood in `shadow` mode; validate scores against real traffic without affecting logins.
2. **Phase 1 — Opt-in enforcement.** Tenant admins can switch to `enforced`. Announce as a beta feature.
3. **Phase 2 — Tune defaults.** Adjust default thresholds based on Phase 0/1 data (false-positive rate on step-up, false-negative rate on known-bad logins from audit history).
4. **Phase 3 (future, out of scope here).** Pluggable learned `Scorer` implementation behind the same port, extend to the authorize-code browser flow and M2M paths.

## 13. Success Metrics

- % of tenants with `mode: "enforced"` 90 days after GA.
- Step-up challenge false-positive rate (user completes MFA successfully on first try after being challenged) — target >90%, i.e., step-ups aren't mostly annoying legitimate users.
- Reduction in successful account-takeover-pattern logins (score ≥ 61 that would previously have succeeded outright), measured via audit log analysis pre/post enablement.
- Zero login-availability incidents attributable to risk-scoring failures (enforced by fail-open design, §7.7).

## 14. Testing Plan

- `domain/risk.Evaluate`: pure unit tests, table-driven, covering every signal combination and boundary score (30/31, 60/61, 80/81) — must hit 100% branch coverage given it's pure logic.
- `application/risk.Service`: unit tests with mocked `DeviceHistoryRepository`/`GeoIPLookup`, including the fail-open path when a port returns an error.
- `application/user.Service.Login`: unit tests for allow/step-up/block outcomes.
- Functional test: real Redis/Postgres-backed device history via testcontainers, login from a "new" vs "known" device.
- E2E test: full login → step-up MFA → verify flow, and a blocked-login flow, added to the existing 141-subtest E2E suite.

## 15. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Geo-IP/device-history dependency causes login latency or outages | Fail-open (§7.7); timeout budget on signal-gathering calls; async-safe defaults |
| Threshold tuning is guesswork initially | Ship shadow mode first (§12 Phase 0) to calibrate against real data before any login is ever blocked |
| Step-up MFA prompts frustrate legitimate users on shared/office IPs | Per-tenant threshold tuning; "known IP" negative weight rewards recurring locations quickly |
| New device-history data store adds infra/ops burden | Reuse existing Postgres/Redis repo patterns and migration tooling — no new infra class |

## 16. Effort Estimate

Matches ROADMAP §3.3: **Large, 2–3 weeks**, ~12 new files / ~3 modified, broken down as:
- Domain + application layer + tests: 3–4 days
- Adapters (geo-IP, device history repo) + migration: 2–3 days
- Wiring into `user.Service` / `auth.Service` + MFA step-up integration: 2–3 days
- Functional + E2E tests: 2–3 days
- Shadow-mode rollout + threshold tuning: ongoing, post-ship

## 17. Open Questions

- Should step-up on a `client_credentials`/M2M-style flow ever apply, or is this strictly for human sessions? (Current recommendation: strictly human, per §4 non-goals.)
- Do we need a dedicated admin read endpoint for risk decisions, or is querying the existing audit API sufficient for v1? (Current recommendation: audit API is sufficient for v1.)
- Geo-IP data source: self-hosted MaxMind GeoLite2 (no external network call, license/update burden) vs. a hosted API (network dependency, simpler ops)? Needs a decision before adapter implementation starts.
