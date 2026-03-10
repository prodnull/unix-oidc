# Phase 7: DPoP Nonce Issuance - Research

**Researched:** 2026-03-10
**Domain:** RFC 9449 DPoP nonce issuance, moka TTL cache, PAM challenge/response, IPC protocol extension
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Must comply with RFC 9449 §8 nonce issuance semantics
- PAM conversation ~512 byte limit is a known constraint; nonce must fit within it
- Current auth flow already supports DPoP proof via `authenticate_with_dpop()` — extend, don't replace
- moka (already chosen in v2.0 decisions) for TTL-bounded nonce cache
- Single-use: a consumed nonce MUST be rejected on second use (hard-fail, never configurable)
- 60-second TTL per success criteria #3
- Cache eviction and capacity limits must follow same patterns as JTI cache (100k entries, DoS-resistant)
- Nonce generation must use CSPRNG (same quality as session ID generation)
- Wire into existing EnforcementMode infrastructure from Phase 6
- Resolve the TODO in auth.rs: "Phase 7: thread dpop_required enforcement mode once DPoP nonce issuance lands"
- `dpop_required: strict` means nonce is mandatory; `warn` means missing nonce logs warning but allows; `disabled` skips nonce check entirely
- Nonce replay (consumed nonce reused) is ALWAYS hard-fail regardless of enforcement mode
- Extend oidc-ssh-agent to receive nonce from PAM and include in DPoP proof
- `DPoPProofClaims` already has `nonce: Option<String>` — no claim struct changes needed

### Claude's Discretion
- All implementation details: nonce format, nonce length, exact cache configuration
- PAM conversation flow design (challenge/response rounds)
- IPC protocol extensions for nonce passing between PAM and agent
- Error message design (generic to client, verbose in server logs per CLAUDE.md)
- Constant-time nonce comparison (already implemented in dpop.rs)
- Test strategy: adversarial tests for replay, expiry, cache exhaustion, timing attacks

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SEC-05 | Server-side DPoP nonce issuance per RFC 9449 §8 with PAM challenge delivery | RFC 9449 §8 nonce semantics documented; PAM two-round flow design provided; nonce generation via getrandom CSPRNG already in codebase |
| SEC-06 | DPoP nonce single-use enforcement and TTL-bounded moka cache | moka 0.12.14 sync::Cache API verified; DPoP nonce cache mirrors JTI cache pattern; single-use via `remove()` on first consumption |
</phase_requirements>

---

## Summary

Phase 7 adds server-side DPoP nonce issuance as specified in RFC 9449 §8. The server generates a fresh nonce per authentication challenge, delivers it to the client via PAM keyboard-interactive, the client embeds it in the next DPoP proof, and the server validates it once against a TTL-bounded single-use cache. Once consumed, the nonce is invalidated; any replay — even within the proof's `iat`/`exp` window and with a valid JTI — is hard-rejected.

The codebase is already structurally ready for this phase. `DPoPConfig.require_nonce` / `DPoPConfig.expected_nonce` and `DPoPProofClaims.nonce` exist. `DPoPValidationError::NonceMismatch` and `MissingNonce` variants are implemented. `constant_time_eq()` is already used for nonce comparison. The PAM `lib.rs` already does multi-step conversation via `pamh.conv()`. The agent `AgentRequest::GetProof` already carries `nonce: Option<String>`. The primary work is: (1) adding a moka-backed `DPoPNonceCache` module, (2) wiring nonce generation into `authenticate_with_dpop()`, (3) implementing two-round PAM conversation for nonce delivery, (4) threading `dpop_required` enforcement mode per the existing TODO at `auth.rs:211`, and (5) wiring the agent to pass received nonces to `generate_dpop_proof()`.

The most subtle design question is the PAM two-round conversation: round 1 issues the nonce as a prompt, round 2 collects the nonce-bound proof. Nonces must fit in the PAM ~512-byte buffer (a 32-byte value in hex or base64url is 64 or 43 bytes, well within budget). The two-round flow is the only approach compatible with PAM's synchronous conversation model and the requirement that nonces be server-generated.

**Primary recommendation:** Add `pam-unix-oidc/src/security/nonce_cache.rs` modeled on `jti_cache.rs`, backed by moka `sync::Cache` with `time_to_live(60s)` and `max_capacity(100_000)`. Nonce generation calls `getrandom::fill()` for 32 bytes encoded as URL-safe base64url (43 chars, fits in PAM buffer). The PAM authenticate function issues nonce on first `conv()` call and collects the proof on a second call. The TODO at `auth.rs:211` resolves by loading `dpop_required` from policy and passing it through the enforcement path.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| moka | 0.12.14 | TTL-bounded single-use nonce cache | Project decision (v2.0 roadmap); lock-free concurrent hash table, no parking_lot needed for cache operations |
| getrandom | 0.3 | CSPRNG for nonce generation | Already in `pam-unix-oidc` Cargo.toml; used by `generate_ssh_session_id()` |
| base64 | 0.21 | URL_SAFE_NO_PAD encoding of nonce bytes | Already in both crates |
| parking_lot | 0.12 | RwLock for any non-moka shared state | Project crate-wide standard since Phase 6 |
| subtle | 2.5 | Constant-time comparison for nonce matching | Already in `pam-unix-oidc`; used in `dpop.rs` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| once_cell | 1.19 | `Lazy<DPoPNonceCache>` global singleton | Same pattern as `DPOP_JTI_CACHE` in dpop.rs |
| uuid | 1 | Not needed for nonces — use raw random bytes | Do NOT use UUID for nonces; random bytes are higher entropy and shorter |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| moka sync::Cache | parking_lot + HashMap (existing JTI pattern) | moka handles TTL eviction automatically; no manual `maybe_cleanup()` needed; handles concurrent inserts without TOCTOU race. Use moka per project decision. |
| 32-byte CSPRNG nonce | UUID v4 | UUIDs are fine entropy but 36 chars vs 43 chars base64url; both fit in PAM buffer. Use raw CSPRNG per project pattern for session IDs. |
| Two-round PAM conversation | Single-round with nonce in prompt suffix | Two-round is cleaner: nonce is clearly a separate challenge value; single-round encoding is brittle. |

**Installation (add to pam-unix-oidc/Cargo.toml):**
```toml
moka = { version = "0.12", features = ["sync"] }
```

Note: moka is NOT yet in `pam-unix-oidc/Cargo.toml`. It must be added. The agent does not need moka (the agent generates proofs, not caches nonces).

---

## Architecture Patterns

### Recommended Project Structure

New files:
```
pam-unix-oidc/src/security/
├── nonce_cache.rs       # NEW: DPoP nonce cache (single-use, TTL-bounded)
├── jti_cache.rs         # existing
├── session.rs           # existing (CSPRNG pattern to reuse)
├── rate_limit.rs        # existing
└── mod.rs               # update: pub mod nonce_cache;
```

No new files in `unix-oidc-agent/` — the IPC protocol already has `nonce: Option<String>` in `GetProof`; the agent `DPoP` signing path already accepts `nonce: Option<&str>`.

### Pattern 1: DPoP Nonce Cache (moka sync, single-use TTL)

**What:** A moka `sync::Cache<String, ()>` where presence of a key means "nonce is valid and has not been consumed." `issue()` inserts with 60s TTL; `consume()` calls `remove()` — returns `Some(())` on first call (valid) and `None` on subsequent calls (replay). Cache auto-evicts expired entries.

**When to use:** Called from `authenticate_with_dpop()` on the server side.

```rust
// Source: moka 0.12.14 docs.rs/moka/sync/struct.Cache.html (HIGH confidence)
use moka::sync::Cache;
use std::time::Duration;

pub struct DPoPNonceCache {
    inner: Cache<String, ()>,
}

impl DPoPNonceCache {
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(Duration::from_secs(ttl_secs))
                .build(),
        }
    }

    /// Issue a new nonce. Returns the nonce string.
    /// Caller must deliver it to the client before calling consume().
    pub fn issue(&self, nonce: &str) {
        self.inner.insert(nonce.to_string(), ());
    }

    /// Consume a nonce. Returns Ok(()) if valid and not yet consumed,
    /// Err(NonceError::Expired) if TTL elapsed,
    /// Err(NonceError::Replayed) if already consumed.
    pub fn consume(&self, nonce: &str) -> Result<(), NonceError> {
        match self.inner.remove(nonce) {
            Some(_) => Ok(()),
            None => {
                // Distinguish: was it ever issued (replay) vs never issued (unknown)?
                // In practice PAM always issues before validating; unknown = already consumed.
                Err(NonceError::ConsumedOrExpired)
            }
        }
    }
}
```

**IMPORTANT:** `moka::sync::Cache::remove()` is the correct single-use primitive. It atomically removes and returns `Some(())` on first call, `None` thereafter. This is the core of single-use enforcement — no separate "check then remove" TOCTOU.

### Pattern 2: Two-Round PAM Conversation

**What:** First `pamh.conv()` call issues the nonce as a prompt text. Second `pamh.conv()` call collects the nonce-bound DPoP proof. This matches how PAM keyboard-interactive works with SSH.

**When to use:** In `lib.rs` `authenticate()` when DPoP nonce mode is active.

```rust
// Source: pamsm crate, PAM spec (HIGH confidence for overall pattern)
// Round 1: Issue nonce as a prompt the client reads
let nonce = generate_dpop_nonce()?; // 32 bytes → base64url
NONCE_CACHE.issue(&nonce);

// Deliver nonce via PAM conversation
// PamMsgStyle::TEXT_INFO sends an informational message the client reads
// The client-side SSH helper reads this and calls agent with the nonce
if let Err(_) = pamh.conv(Some(&format!("DPOP_NONCE:{}", nonce)), PamMsgStyle::TEXT_INFO) {
    return PamError::AUTH_ERR;
}

// Round 2: Collect the nonce-bound proof
let proof = match pamh.conv(Some("DPOP_PROOF: "), PamMsgStyle::PROMPT_ECHO_OFF) {
    Ok(Some(p)) => p.to_string_lossy().to_string(),
    _ => return PamError::AUTH_ERR,
};
```

**NOTE:** The exact PAM message style for nonce delivery requires careful thought (see Pitfall 2 below). The client side must be adapted to recognize and parse the `DPOP_NONCE:` prefix.

### Pattern 3: Nonce Generation

**What:** 32 bytes from CSPRNG, encoded as URL-safe base64url without padding = 43 chars. Fits in PAM 512-byte buffer. Identical entropy to session IDs but longer for nonce use cases.

```rust
// Source: pam-unix-oidc/src/security/session.rs pattern (HIGH confidence)
pub fn generate_dpop_nonce() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    getrandom::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
```

### Pattern 4: Enforcement Mode Threading (resolve TODO at auth.rs:211)

**What:** Load `dpop_required` from `PolicyConfig::effective_security_modes()` and pass it into the nonce validation path. Same pattern as `jti_enforcement` already threaded at auth.rs:83-85.

```rust
// Source: pam-unix-oidc/src/auth.rs:83-85 pattern (HIGH confidence)
if let Ok(policy) = PolicyConfig::from_env() {
    let modes = policy.effective_security_modes();
    config.jti_enforcement = modes.jti_enforcement;
    // Phase 7: Now also thread dpop_required
    dpop_auth_config.nonce_enforcement = modes.dpop_required;
}
```

The `dpop_required` `EnforcementMode` governs whether a *missing* nonce causes hard-fail (strict), warning (warn), or is skipped (disabled). It NEVER governs nonce replay — replay is always hard-fail per CLAUDE.md invariant.

### Anti-Patterns to Avoid

- **Check-then-remove TOCTOU:** Never `contains_key()` then `remove()` for single-use enforcement. Use only `remove()` — its return value is the atomic check-and-remove.
- **Global Lazy<HashMap> for nonce cache:** The existing JTI cache in `dpop.rs` uses `parking_lot::RwLock<HashMap>` with manual cleanup. For the nonce cache, use moka (project decision). Do not add another manual-cleanup HashMap cache.
- **Storing nonce in DPoPAuthConfig.expected_nonce:** The existing `DPoPAuthConfig.expected_nonce` is a single `Option<String>`. With a cache, multiple nonces can be live simultaneously (concurrent auth sessions). The cache lookup replaces this field — don't extend the single-value pattern.
- **Large nonces that exceed PAM buffer:** PAM conversation is ~512 bytes. A 32-byte CSPRNG nonce base64url-encoded is 43 chars + prefix "DPOP_NONCE:" (11 chars) = 54 chars total. Well within budget. Do not use longer nonces.
- **Making nonce replay configurable:** The CONTEXT.md and CLAUDE.md are explicit: nonce replay is in the same invariant class as JTI replay. The `EnforcementMode` controls missing-nonce behavior, not consumed-nonce behavior.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TTL cache with auto-eviction | Manual HashMap + `retain()` + interval timer | `moka::sync::Cache` with `time_to_live()` | moka handles eviction automatically; no background thread needed in PAM; no manual cleanup interval code |
| Atomic single-use check | Read lock, check, write lock, remove (TOCTOU race) | `moka::sync::Cache::remove()` | Returns `Option<V>` atomically; first call returns `Some`, second returns `None` |
| CSPRNG nonce | `rand::random()` or timestamp-based nonce | `getrandom::fill()` (already in Cargo.toml) | Already available; OS-backed CSPRNG; no new dep |

---

## Common Pitfalls

### Pitfall 1: TOCTOU Race in Single-Use Enforcement

**What goes wrong:** Using `contains_key()` to check existence then `invalidate()` to remove allows two concurrent threads to both see the nonce as present.

**Why it happens:** PAM can authenticate multiple users concurrently; `sshd` forks per connection.

**How to avoid:** Use `remove()` exclusively. The return value is the atomic check-and-consume: `Some(_)` = first use (valid), `None` = already consumed or expired.

**Warning signs:** Any code that calls `contains_key` followed by `invalidate` or `remove` is wrong.

### Pitfall 2: PAM Message Style for Nonce Delivery

**What goes wrong:** Using `PamMsgStyle::PROMPT_ECHO_OFF` for the nonce delivery sends an *interactive prompt* waiting for client input before proceeding. The client would need to respond to this round with something before round 2. Using `TEXT_INFO` sends a one-way message the client can read without responding — but not all PAM conversation implementations handle `TEXT_INFO` messages cleanly over SSH keyboard-interactive.

**Why it happens:** PAM conversation has multiple message styles (`PROMPT_ECHO_OFF`, `PROMPT_ECHO_ON`, `TEXT_INFO`, `ERROR_MSG`). Their behavior depends on the PAM client (sshd, sudo, etc.).

**How to avoid:** Use `PamMsgStyle::PROMPT_ECHO_ON` for the nonce delivery round (the client is expected to "respond" with an empty string or acknowledgment), then use `PROMPT_ECHO_OFF` for the proof round. The agent client-side helper recognizes the `DPOP_NONCE:` prefix in the prompt and stores the nonce for the next proof request. This is how two-round keyboard-interactive works in practice.

**Warning signs:** Auth hangs at nonce delivery step; client reports "Authentication failed" without reaching proof submission.

### Pitfall 3: moka sync::Cache in a cdylib PAM Module

**What goes wrong:** moka's sync cache spawns background threads for eviction scheduling. A `cdylib` loaded into sshd cannot guarantee those threads are joined before `dlclose()`. On Linux this is typically safe (threads are orphaned and cleaned up by the OS), but it can cause issues in test frameworks that fork.

**Why it happens:** moka uses a background eviction thread by default.

**How to avoid:** moka 0.12's `sync::Cache` performs eviction lazily on read/write operations when TTL is set, and the background maintenance thread is lightweight. The existing `DPOP_JTI_CACHE` already uses `parking_lot::RwLock<HashMap>` as a `Lazy` global in a cdylib — the same pattern applies. Initialize the nonce cache as `Lazy<DPoPNonceCache>` in the `once_cell` pattern. Verify in integration tests that the daemon does not crash on unload.

**Warning signs:** Tests with `cargo test` crash intermittently; valgrind reports thread errors.

### Pitfall 4: Nonce Cache Capacity and DoS

**What goes wrong:** An attacker triggers many PAM authentication attempts, each issuing a nonce that occupies cache memory, exhausting 100k slots before any authenticate.

**Why it happens:** Rate limiting is upstream of nonce issuance, but each auth attempt issues a nonce before validating the token.

**How to avoid:** Issue nonce AFTER rate-limit check (rate limiter is already called before token collection in `lib.rs`). moka's `max_capacity(100_000)` will silently evict oldest entries when full — on a nonce cache this means the evicted nonce can no longer be validated. This is safe: the legitimate client will receive `AUTH_ERR` and can retry. Log a warning when cache is at capacity.

**Warning signs:** Legitimate users fail authentication during DoS; cache size metric at ceiling.

### Pitfall 5: Nonce Not Passed Through IPC to Agent

**What goes wrong:** The PAM module issues a nonce and the client-side SSH helper reads it, but the nonce is not forwarded in the `AgentRequest::GetProof` IPC message, so the agent generates a proof without the nonce claim.

**Why it happens:** The IPC already has `nonce: Option<String>` in `GetProof` — this was added in advance. But the SSH helper that calls the agent must extract the nonce from the PAM conversation prompt and pass it in the IPC request.

**How to avoid:** The client-side SSH helper (or `oidc-ssh-agent get-proof` subcommand path) must parse the `DPOP_NONCE:<value>` prefix from the PAM conversation response and pass it as `nonce` in the `GetProof` IPC request. The agent's `build_dpop_message()` already accepts `nonce: Option<&str>` and includes it in claims.

**Warning signs:** Server rejects proofs with `NonceMismatch` even when client reads nonce correctly; nonce in proof is `null` in claims.

---

## Code Examples

Verified patterns from official sources and existing codebase:

### Nonce Cache Using moka sync::Cache

```rust
// Source: moka 0.12.14 docs.rs/moka/sync/struct.Cache.html (HIGH confidence)
use moka::sync::Cache;
use once_cell::sync::Lazy;
use std::time::Duration;

const MAX_NONCE_ENTRIES: u64 = 100_000;
const NONCE_TTL_SECS: u64 = 60;

static DPOP_NONCE_CACHE: Lazy<DPoPNonceCache> = Lazy::new(DPoPNonceCache::new);

pub struct DPoPNonceCache {
    inner: Cache<String, ()>,
}

impl DPoPNonceCache {
    pub fn new() -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(MAX_NONCE_ENTRIES)
                .time_to_live(Duration::from_secs(NONCE_TTL_SECS))
                .build(),
        }
    }

    /// Issue a new nonce into the cache.
    pub fn issue(&self, nonce: &str) {
        self.inner.insert(nonce.to_string(), ());
    }

    /// Consume a nonce atomically. Returns Ok on first use; Err on replay or expiry.
    /// Single-use invariant: moka::remove() is atomic — first call returns Some, all
    /// subsequent calls return None regardless of TTL.
    pub fn consume(&self, nonce: &str) -> Result<(), NonceConsumeError> {
        match self.inner.remove(nonce) {
            Some(_) => Ok(()),
            None => Err(NonceConsumeError::ConsumedOrExpired),
        }
    }
}
```

### Nonce Generation (256-bit CSPRNG)

```rust
// Source: pam-unix-oidc/src/security/session.rs generate_random_bytes() pattern (HIGH confidence)
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub fn generate_dpop_nonce() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32]; // 256-bit entropy
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
    // Result: 43-char URL-safe base64url string, no padding
    // Fits in PAM ~512 byte buffer with room to spare
}
```

### Enforcement Mode Decision (missing nonce)

```rust
// Source: pam-unix-oidc/src/policy/config.rs EnforcementMode pattern (HIGH confidence)
// Mirrors the jti_enforcement pattern at auth.rs:213-215
match (nonce_in_proof, enforcement_mode) {
    (None, EnforcementMode::Strict) => {
        tracing::warn!(check = "dpop_nonce", mode = "strict", outcome = "reject",
            "DPoP nonce required but missing from proof");
        return Err(DPoPValidationError::MissingNonce);
    }
    (None, EnforcementMode::Warn) => {
        tracing::warn!(check = "dpop_nonce", mode = "warn", outcome = "allow",
            "DPoP nonce missing from proof (warn mode)");
        // allow, no nonce validation
    }
    (None, EnforcementMode::Disabled) => {
        // skip nonce check entirely
    }
    (Some(nonce), _) => {
        // validate against cache — ALWAYS hard-fail on replay regardless of mode
        DPOP_NONCE_CACHE.consume(nonce)
            .map_err(|_| DPoPValidationError::NonceMismatch)?;
    }
}
```

### Cargo.toml Addition

```toml
# pam-unix-oidc/Cargo.toml [dependencies]
moka = { version = "0.12", features = ["sync"] }
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| DPoP proofs protected only by iat/exp + JTI | iat/exp + JTI + server-issued nonce | RFC 9449 finalized (2023, RFC 9449) | Nonce makes replay impossible even if attacker captures proof within its validity window |
| Manual HashMap + parking_lot cleanup for replay caches | moka sync::Cache with TTL auto-eviction | v2.0 roadmap decision | Eliminates TOCTOU in check-then-remove; no manual cleanup interval; smaller code |

**RFC 9449 §8 normative summary (HIGH confidence — verified from rfc-editor.org):**
- Server supplies nonce via `DPoP-Nonce` HTTP header (or PAM message in our case)
- Client includes nonce in `nonce` claim of DPoP proof
- If nonce is wrong/missing, server responds with `use_dpop_nonce` error and new nonce
- Our PAM adaptation: nonce delivered in `DPOP_NONCE:<value>` prompt, proof submitted in second conversation round
- Nonce syntax: `1*NQCHAR` per RFC 9449 §8.1 — base64url chars are valid NQCHAR

---

## Open Questions

1. **PAM conversation style for nonce delivery**
   - What we know: `pamsm::PamMsgStyle` has `TEXT_INFO`, `PROMPT_ECHO_ON`, `PROMPT_ECHO_OFF`, `ERROR_MSG`. sshd keyboard-interactive honors `PROMPT_ECHO_OFF` for secrets and `TEXT_INFO` for informational messages. The client SSH helper (`SSH_ASKPASS` or the agent's PAM client hook) must be adapted to parse `DPOP_NONCE:` prefix.
   - What's unclear: Whether the existing agent's PAM integration path uses `SSH_ASKPASS` or a custom keyboard-interactive handler. This affects how the nonce is extracted from the PAM conversation on the client side.
   - Recommendation: Review `unix-oidc-agent/src/` for PAM client integration code. If `SSH_ASKPASS` is used, the script must output the nonce to the agent before generating the proof. If keyboard-interactive is handled in the agent daemon directly, the `GetProof` IPC call is made before answering round 2.

2. **moka sync vs mini-moka for cdylib**
   - What we know: moka 0.12 spawns maintenance threads. `mini-moka` is the no-background-thread variant.
   - What's unclear: Whether background threads cause issues in PAM cdylib context over the lifetime of `sshd` running many auths.
   - Recommendation: Use full `moka::sync::Cache` per project decision. The `DPOP_JTI_CACHE` static already uses a `Lazy` global in dpop.rs; add `DPOP_NONCE_CACHE` on the same pattern. If thread issues arise in CI, switch to `mini-moka` (same API, `features = ["sync"]`).

3. **Where to locate the nonce cache initialization**
   - What we know: JTI cache is `Lazy` global in `dpop.rs` (within the oidc module). The nonce cache is conceptually a server-side security mechanism.
   - Recommendation: Place in `pam-unix-oidc/src/security/nonce_cache.rs`, consistent with `jti_cache.rs` location. Export via `security::mod.rs`.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (`cargo test`) |
| Config file | none — inline `#[cfg(test)]` modules per crate convention |
| Quick run command | `cargo test -p pam-unix-oidc --lib 2>&1 \| tail -20` |
| Full suite command | `cargo test --workspace 2>&1 \| tail -30` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEC-05 | Nonce issued per auth, delivered in PAM conversation, embedded in DPoP proof | unit | `cargo test -p pam-unix-oidc security::nonce_cache -x` | Wave 0 |
| SEC-05 | Nonce generation produces unique 43-char base64url values | unit | `cargo test -p pam-unix-oidc generate_dpop_nonce` | Wave 0 |
| SEC-06 | Nonce consumed once; second use returns ConsumedOrExpired | unit | `cargo test -p pam-unix-oidc nonce_consume_single_use` | Wave 0 |
| SEC-06 | Nonce expired after 60s TTL; consumed nonce rejected | unit | `cargo test -p pam-unix-oidc nonce_expired_rejected` | Wave 0 |
| SEC-06 | Nonce replay hard-fails regardless of dpop_required enforcement mode | unit | `cargo test -p pam-unix-oidc nonce_replay_always_hard_fail` | Wave 0 |
| SEC-06 | Missing nonce with strict mode rejects auth | unit | `cargo test -p pam-unix-oidc nonce_missing_strict_rejects` | Wave 0 |
| SEC-06 | Missing nonce with warn mode allows auth | unit | `cargo test -p pam-unix-oidc nonce_missing_warn_allows` | Wave 0 |
| SEC-06 | Cache at max_capacity does not panic | unit | `cargo test -p pam-unix-oidc nonce_cache_capacity_exhaustion` | Wave 0 |
| SEC-05 | Agent GetProof IPC passes nonce to DPoP proof | unit | `cargo test -p unix-oidc-agent dpop_proof_includes_nonce` | Wave 0 |

### Adversarial Tests (per CLAUDE.md standing directive)
| Attack | Test | Hard-fail? |
|--------|------|------------|
| Replay consumed nonce | `nonce_replay_always_hard_fail` | Always |
| Expired nonce reused | `nonce_expired_rejected` | Always |
| Malformed nonce (non-NQCHAR) | `nonce_malformed_rejected` | Always |
| Cache exhaustion (100k+1 issues) | `nonce_cache_capacity_exhaustion` | No panic, oldest evicted |
| Timing side-channel (constant-time compare) | `nonce_compare_constant_time` | N/A (verify use of `subtle::ConstantTimeEq`) |
| Zero-length nonce | `nonce_empty_rejected` | Always |

### Sampling Rate
- **Per task commit:** `cargo test -p pam-unix-oidc --lib 2>&1 | tail -20`
- **Per wave merge:** `cargo test --workspace 2>&1 | tail -30`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `pam-unix-oidc/src/security/nonce_cache.rs` — covers SEC-06 single-use, TTL, capacity
- [ ] Tests in `nonce_cache.rs` `#[cfg(test)]` block covering all adversarial cases above
- [ ] `pam-unix-oidc` Cargo.toml: `moka = { version = "0.12", features = ["sync"] }` — dependency not yet present

---

## Sources

### Primary (HIGH confidence)
- RFC 9449 §8 (rfc-editor.org) — DPoP nonce issuance semantics, nonce syntax, error responses
- moka 0.12.14 (docs.rs/moka/0.12.14/moka/sync/struct.Cache.html) — `Cache::remove()` atomic API, `CacheBuilder::time_to_live()`, `max_capacity()`
- `pam-unix-oidc/src/oidc/dpop.rs` — existing `DPoPConfig`, `DPoPProofClaims.nonce`, `constant_time_eq`, `DPoPValidationError` variants
- `pam-unix-oidc/src/auth.rs` — `authenticate_with_dpop()`, TODO at line 211, enforcement threading pattern
- `pam-unix-oidc/src/policy/config.rs` — `EnforcementMode`, `SecurityModes.dpop_required`, figment config loading
- `pam-unix-oidc/src/security/session.rs` — `generate_random_bytes()` CSPRNG pattern
- `pam-unix-oidc/src/security/jti_cache.rs` — reference implementation pattern for nonce cache structure
- `unix-oidc-agent/src/daemon/protocol.rs` — `AgentRequest::GetProof` already has `nonce: Option<String>`
- `unix-oidc-agent/src/crypto/dpop.rs` — `generate_dpop_proof()` and `build_dpop_message()` already accept `nonce: Option<&str>`

### Secondary (MEDIUM confidence)
- Workspace `Cargo.toml` and crate `Cargo.toml` files — confirmed moka is not yet a dependency of `pam-unix-oidc`; getrandom 0.3, base64 0.21, parking_lot 0.12, subtle 2.5 all present

### Tertiary (LOW confidence)
- None — all claims verified from primary sources

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in workspace or verified on crates.io; moka API verified on docs.rs
- Architecture: HIGH — patterns extrapolated directly from existing codebase code paths
- Pitfalls: HIGH — derived from RFC spec, moka behavior, PAM conversation model, and TOCTOU analysis of the existing JTI cache pattern

**Research date:** 2026-03-10
**Valid until:** 2026-06-10 (moka API is stable; RFC 9449 is published; PAM model is unchanged)
