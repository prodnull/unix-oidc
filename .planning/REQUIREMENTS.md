# Requirements: unix-oidc v2.2 Hardening & Conformance

**Defined:** 2026-03-14
**Core Value:** DPoP private keys must be protected at rest, in memory, and on deletion — and every security finding, tech debt item, and observability gap must be closed before shipping new capabilities.

## v2.2 Requirements

### Security Bug Fixes

- [x] **SBUG-01**: `source_ip` passed as `oidc_issuer` in all `token_validation_failed()` call sites is corrected — forensic attribution works
- [x] **SBUG-02**: `BreakGlassConfig.alert_on_use` wired to runtime syslog elevation — operators get the elevated severity they configured
- [x] **SBUG-03**: `TokenClaims.preferred_username` is `Option<String>` per OIDC Core §5.1 — tokens from Google/Azure without the claim don't panic

### Security Hardening

- [x] **SHRD-01**: Algorithm comparison in `validation.rs` uses explicit enum match, not Debug format strings
- [x] **SHRD-02**: Algorithm allowlist enforced when JWKS key omits `alg` field — HS256-with-RSA-public-key attack prevented
- [x] **SHRD-03**: Syslog severity mapped to audit event severity — `BREAK_GLASS_AUTH` logged at CRITICAL, not INFO
- [x] **SHRD-04**: HTTPS scheme validated for OIDC issuer URL at config load time and for device flow `verification_uri`
- [x] **SHRD-05**: Terminal escape sequences sanitized in IdP-supplied `verification_uri` before display
- [x] **SHRD-06**: D-Bus Secret Service rejects plain (unencrypted) sessions; `reject_plain_dbus_sessions: strict/warn/disabled` config toggle

### Tech Debt

- [x] **DEBT-01**: All `unwrap_used`/`expect_used` lint violations fixed across pam-unix-oidc (audit.rs, ciba/client.rs, ciba/types.rs, device_flow/client.rs, approval/provider.rs, sudo.rs) — token-exchange CI job unblocked
- [x] **DEBT-02**: ACR mapping enforcement wired in multi-issuer auth path (currently `required_acr: None`)
- [x] **DEBT-03**: `GroupSource::TokenClaim` path exercised in auth pipeline or dead code removed
- [x] **DEBT-04**: `effective_issuers()` backward-compat function wired into production dispatch or removed
- [x] **DEBT-05**: JWKS TTL and HTTP timeout configurable per-issuer (currently hardcoded 300s/10s)
- [x] **DEBT-06**: Entra CI ROPC token step has fallback diagnostic if Conditional Access blocks ROPC
- [x] **DEBT-07**: Minor v2.0 residuals cleaned up (socket.rs unwrap, clippy test annotations)
- [x] **DEBT-08**: `secure_delete.rs` primary citation updated from DoD 5220.22-M to NIST SP 800-88 Rev 1 §2.4

### Multi-IdP Advanced

- [ ] **MIDP-09**: IdP priority ordering — issuers tried in configured order
- [ ] **MIDP-10**: IdP health monitoring — issuer marked degraded if JWKS fetch fails, with recovery
- [ ] **MIDP-11**: Hot-reload of issuer config without daemon restart

### Observability & Compliance

- [ ] **OBS-02**: No-token authentication attempts produce structured audit events
- [x] **OBS-04**: Key lifecycle events (generation, loading, destruction) are structured audit events, not tracing-only
- [x] **OBS-05**: Log retention controls and logrotate integration documented and shipped
- [ ] **OBS-06**: Audit log tamper-evidence via hash chain or HMAC
- [ ] **OBS-07**: OCSF schema fields in audit events for SIEM interoperability
- [ ] **OBS-08**: IPC session-close failures audited (missed revocations no longer silently dropped)
- [x] **OBS-09**: GDPR Article 17 erasure path documented with implementation guidance

### Documentation & Conformance

- [ ] **DOC-01**: Standards compliance matrix at `docs/standards-compliance-matrix.md` — RFC-to-file mapping, NIST/SOC2 cross-refs, implementation status
- [ ] **DOC-02**: Identity rationalization guide — FreeIPA + Entra coexistence patterns, UPN-to-uid mapping, group sync
- [ ] **DOC-03**: JTI cache architecture documented — per-process cache in forked-sshd model, DPoP nonces as actual replay defense

### E2E Test Coverage

- [ ] **E2ET-01**: Automated DPoP nonce two-round keyboard-interactive flow over SSH with replay rejection
- [ ] **E2ET-02**: Break-glass end-to-end PAM flow with real NSS group policy denial
- [ ] **E2ET-03**: PAM putenv/getenv cross-fork session ID correlation + SessionClosed IPC roundtrip + auto-refresh
- [ ] **E2ET-04**: Full CIBA flow against real IdP + FIDO2 ACR delegation E2E + concurrent step-up guard
- [ ] **E2ET-05**: systemd socket activation E2E + launchd install/uninstall + JSON log under journald + graceful shutdown

## Future Requirements (v3.0+)

### Capabilities (v3.0)

- **CAP-01**: SCIM integration for user provisioning
- **CAP-02**: AI Agent Delegation — parse `act`/`azp` claims, scope-limited auth (RFC 8693 Token Exchange)
- **CAP-03**: Hardware key attestation
- **CAP-04**: Centralized audit log shipping
- **CAP-05**: Pentest automation suite (token manipulation, PAM memory safety, network/TLS, rate limiting)
- **CAP-06**: FIPS-validated Rust crypto libraries / OpenSSL FIPS module
- **CAP-07**: PAM binary signing (MITRE ATT&CK T1556 mitigation)
- **CAP-08**: Push notification step-up method
- **CAP-09**: FIDO2/WebAuthn step-up method (beyond ACR enforcement)
- **CAP-10**: Break-glass with offline YubiKey OTP
- **CAP-11**: CIBA `login_hint_claim` config for IdPs expecting email
- **CAP-12**: Blocking HTTP offload to agent daemon (ARCH-3)

### External IdP Integration Testing (v3.1)

- **IDPX-01**: Okta integration tests (CIBA push-only mode detection)
- **IDPX-02**: Auth0 integration tests (device flow + token validation)
- **IDPX-03**: Google Cloud Identity integration tests

## Out of Scope

| Feature | Reason |
|---------|--------|
| Distributed JTI cache (Redis) | Separate scalability milestone |
| VDI/agent forwarding | Anti-feature: breaks PAM non-interactive model and threat model |
| Interactive PIN during PAM auth | Anti-feature: PAM is non-interactive by design |
| SAML integration | unix-oidc is OIDC-only by design |
| reqwest 0.11→0.13 upgrade | Separate hardening task (TLS layer audit required) |
| New product capabilities (SCIM, AI Agent, etc.) | v3.0 milestone |
| External IdP live tests (Okta, Auth0, Google) | v3.1 milestone |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SBUG-01 | Phase 24 | Complete |
| SBUG-02 | Phase 24 | Complete |
| SBUG-03 | Phase 24 | Complete |
| SHRD-01 | Phase 25 | Complete |
| SHRD-02 | Phase 25 | Complete |
| SHRD-03 | Phase 25 | Complete |
| SHRD-04 | Phase 25 | Complete |
| SHRD-05 | Phase 25 | Complete |
| SHRD-06 | Phase 25 | Complete |
| DEBT-01 | Phase 24 | Complete |
| DEBT-02 | Phase 26 | Complete |
| DEBT-03 | Phase 26 | Complete |
| DEBT-04 | Phase 26 | Complete |
| DEBT-05 | Phase 26 | Complete |
| DEBT-06 | Phase 26 | Complete |
| DEBT-07 | Phase 24 | Complete |
| DEBT-08 | Phase 26 | Complete |
| MIDP-09 | Phase 27 | Pending |
| MIDP-10 | Phase 27 | Pending |
| MIDP-11 | Phase 27 | Pending |
| OBS-02 | Phase 27 | Pending |
| OBS-04 | Phase 27 | Complete |
| OBS-05 | Phase 27 | Complete |
| OBS-06 | Phase 27 | Pending |
| OBS-07 | Phase 27 | Pending |
| OBS-08 | Phase 27 | Pending |
| OBS-09 | Phase 27 | Complete |
| DOC-01 | Phase 28 | Pending |
| DOC-02 | Phase 28 | Pending |
| DOC-03 | Phase 28 | Pending |
| E2ET-01 | Phase 28 | Pending |
| E2ET-02 | Phase 28 | Pending |
| E2ET-03 | Phase 28 | Pending |
| E2ET-04 | Phase 28 | Pending |
| E2ET-05 | Phase 28 | Pending |

**Coverage:**
- v2.2 requirements: 35 total (SBUG x3, SHRD x6, DEBT x8, MIDP x3, OBS x7, DOC x3, E2ET x5)
- Mapped to phases: 35
- Unmapped: 0

---
*Requirements defined: 2026-03-14*
*Last updated: 2026-03-14 — traceability complete after roadmap creation*
