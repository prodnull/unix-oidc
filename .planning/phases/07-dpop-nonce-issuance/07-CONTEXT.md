# Phase 7: DPoP Nonce Issuance - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

The server issues a fresh single-use nonce with every DPoP challenge, making captured DPoP proofs unreplayable even within their `iat`/`exp` window. Implements SEC-05 (server-side DPoP nonce issuance per RFC 9449 §8 with PAM challenge delivery) and SEC-06 (DPoP nonce single-use enforcement and TTL-bounded moka cache).

</domain>

<decisions>
## Implementation Decisions

### Nonce Delivery Mechanism
- Claude's Discretion — design the optimal PAM challenge/response flow for nonce delivery
- Must comply with RFC 9449 §8 nonce issuance semantics
- PAM conversation ~512 byte limit is a known constraint; nonce must fit within it
- Current auth flow already supports DPoP proof via `authenticate_with_dpop()` — extend, don't replace
- Consider two-round PAM conversation: first round issues nonce, second round receives nonce-bound proof

### Nonce Lifecycle & Cache
- Claude's Discretion — use moka (already chosen in v2.0 decisions) for TTL-bounded nonce cache
- Single-use: a consumed nonce MUST be rejected on second use (hard-fail, never configurable)
- 60-second TTL per success criteria #3
- Cache eviction and capacity limits must follow same patterns as JTI cache (100k entries, DoS-resistant)
- Nonce generation must use CSPRNG (same quality as session ID generation)

### Enforcement Integration
- Claude's Discretion — wire into existing EnforcementMode infrastructure from Phase 6
- Resolve the TODO in auth.rs: "Phase 7: thread dpop_required enforcement mode once DPoP nonce issuance lands"
- `dpop_required: strict` means nonce is mandatory; `warn` means missing nonce logs warning but allows; `disabled` skips nonce check entirely
- Nonce replay (consumed nonce reused) is ALWAYS hard-fail regardless of enforcement mode — same invariant as JTI replay

### Client-Side Nonce Handling
- Claude's Discretion — extend oidc-ssh-agent to receive nonce from PAM and include in DPoP proof
- Agent already has DPoP signing infrastructure; needs nonce injection into proof `nonce` claim
- `DPoPProofClaims` already has `nonce: Option<String>` field
- IPC protocol may need extension for nonce passing

### Claude's Discretion
- All implementation details: nonce format, nonce length, exact cache configuration
- PAM conversation flow design (challenge/response rounds)
- IPC protocol extensions for nonce passing between PAM and agent
- Error message design (generic to client, verbose in server logs per CLAUDE.md)
- Constant-time nonce comparison (already implemented in dpop.rs)
- Test strategy: adversarial tests for replay, expiry, cache exhaustion, timing attacks

</decisions>

<specifics>
## Specific Ideas

- Standing directive: ultra secure, standards/best practice compliant, enterprise ready, fully audited and tested
- Every security feature must include adversarial/negative tests (malformed nonces, replayed nonces, expired nonces, cache exhaustion, timing attacks)
- Follow RFC 9449 §8 precisely for nonce semantics
- Nonce replay is in the same invariant class as JTI replay — NEVER configurable, always hard-fail
- Match the patterns established in Phase 6 (EnforcementMode, figment config, parking_lot, moka)

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DPoPConfig` (`pam-unix-oidc/src/oidc/dpop.rs`): Already has `require_nonce: bool` and `expected_nonce: Option<String>` fields — wire to nonce cache
- `DPoPProofClaims` (`pam-unix-oidc/src/oidc/dpop.rs`): Already has `nonce: Option<String>` — no claim struct changes needed
- `DPoPValidationError::NonceMismatch` and `MissingNonce` variants already exist
- `constant_time_eq()` in dpop.rs — already used for nonce comparison
- `DPoPJtiCache` — pattern for nonce cache (similar structure: check_and_record, TTL, cleanup)
- `EnforcementMode` (`pam-unix-oidc/src/policy/config.rs`): Reuse for nonce enforcement configuration
- `SecurityModes` (`pam-unix-oidc/src/policy/config.rs`): `dpop_required` field already exists — extend semantics to cover nonce
- `generate_ssh_session_id()` (`pam-unix-oidc/src/security/session.rs`): CSPRNG pattern for nonce generation
- `CacheConfig` (`pam-unix-oidc/src/policy/config.rs`): Pattern for operational cache tuning — add nonce cache params

### Established Patterns
- `parking_lot::RwLock` — crate-wide locking primitive (Phase 6 migration complete)
- `moka` — chosen for all TTL caches per v2.0 roadmap decisions
- `thiserror` for error types — use for any new error variants
- `tracing` structured logging — enforcement mode decisions logged with check name, mode, and outcome
- `deny(clippy::unwrap_used, clippy::expect_used)` — all new code must comply
- figment-based config — any new config fields use same layered loading pattern

### Integration Points
- `pam-unix-oidc/src/auth.rs`: `authenticate_with_dpop()` — extend to generate nonce and populate `DPoPConfig.expected_nonce`
- `pam-unix-oidc/src/auth.rs:211`: TODO comment marks exact insertion point for dpop_required enforcement threading
- `pam-unix-oidc/src/lib.rs`: `authenticate()` PAM entry point — may need two-round conversation for nonce challenge/response
- `pam-unix-oidc/src/oidc/dpop.rs`: `validate_dpop_proof()` — nonce validation already implemented, just needs cache-backed expected nonce
- `unix-oidc-agent/src/daemon/protocol.rs`: IPC protocol — may need nonce field in proof request/response
- `unix-oidc-agent/src/crypto/dpop.rs`: Client-side DPoP proof creation — needs nonce parameter
- `pam-unix-oidc/src/policy/config.rs`: `SecurityModes.dpop_required` — semantics extend to cover nonce requirement

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 07-dpop-nonce-issuance*
*Context gathered: 2026-03-10*
