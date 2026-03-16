# Milestones

## v2.2 Hardening & Conformance (Shipped: 2026-03-16)

**Phases completed:** 21 phases, 57 plans, 29 tasks

**Key accomplishments:**
- (none recorded)

---

## v2.1 Integration Testing Infrastructure (Shipped: 2026-03-14)

**Phases completed:** 6 phases (18-23), 8 plans
**Requirements:** 30/30 satisfied
**Audit:** `.planning/v2.1-MILESTONE-AUDIT.md` — COMPLETE

**Key accomplishments:**
- Full SSH E2E test chain with real Keycloak JWKS signature verification (no TEST_MODE)
- Playwright-automated device flow consent for headless CI
- Multi-IdP configuration with per-issuer DPoP enforcement, claim mapping, ACR mapping
- Azure Entra ID bearer-only integration with RS256 validation and UPN mapping
- keycloak-e2e CI job gating every push to main
- Cross-phase integration gaps closed (DPoP nonce consumption, Entra fixture coverage)

---

## v2.0 Production Hardening & Enterprise Readiness (Shipped: 2026-03-13)

**Phases completed:** 12 phases (6-17), 29 plans
**Requirements:** 50/50 satisfied (44 at audit, 6 closed via gap phases 14-16)
**Audit:** `.planning/v2.0-MILESTONE-AUDIT.md` — COMPLETE

**Key accomplishments:**
- PAM panic elimination with deny(clippy::unwrap_used) lint
- DPoP nonce issuance with single-use nonce cache and two-round PAM conversation
- Username mapping, group policy, break-glass bypass with audit trail
- Token introspection, session lifecycle, auto-refresh
- CIBA step-up authentication with FIDO2 via ACR delegation
- Operational hardening (systemd/launchd, peer-auth IPC, structured tracing)
- ML-DSA-65+ES256 hybrid PQC DPoP support
- Structured audit events, sudo session linking, session expiry sweep

---

## v1.0 Client-Side Key Protection Hardening (Shipped: 2026-03-10)

**Phases completed:** 5 phases (1-5), 12 plans
**Requirements:** All satisfied

**Key accomplishments:**
- Memory-locked DPoP signing keys with ZeroizeOnDrop
- Probe-based storage backend selection (Secret Service/Keychain > keyutils > file)
- Atomic migration with rollback between storage backends
- Hardware signer backends (YubiKey PKCS#11, TPM tss-esapi)
- Secure credential deletion with DoD 5220.22-M overwrite + CoW/SSD advisories
- Core dumps disabled, OAuth tokens in SecretString

---
