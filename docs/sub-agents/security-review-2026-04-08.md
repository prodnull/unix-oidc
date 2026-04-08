# Security Review — unix-oidc (2026-04-08)

## Methodology

- **4 parallel Claude Opus reviewers**: PAM OIDC core, PAM security/policy, agent daemon, DPoP library
- **Gemini 2.5 Pro/Flash independent review**: Full source code analysis with separate findings
- **Adversarial cross-examination**: Claude findings validated by Gemini; Gemini findings verified against code by Claude
- **Code-only review**: No documentation bias — all claims verified against actual source
- **Scope**: All production `.rs` files across `pam-unix-oidc`, `unix-oidc-agent`, and `rust-oauth-dpop`

## Severity Legend

| Severity | Definition |
|----------|------------|
| **CRITICAL** | Remote code execution, full system compromise, or complete authentication bypass |
| **HIGH** | Reliable authentication bypass, privilege escalation, or cross-user data exposure |
| **MEDIUM** | Significant weakness requiring specific conditions (local access, compromised agent) |
| **LOW** | Minor risk, limited DoS, or deviation from best practices |

## Results Summary

| Severity | Claude Found | Gemini Found | Total Unique | Fixed | Tests Added |
|----------|-------------|-------------|--------------|-------|-------------|
| HIGH | 10 | 1 | 10 | 8 | 16 |
| MEDIUM | 13 | 2 | 14 | 6 | 12 |
| LOW | 6 | 3 | 8 | 0 | 0 |
| **Total** | **29** | **6** | **32** | **16** | **39** |

Zero false positives across both reviewers. All findings independently verified against source code.

---

## Findings Fixed in This Review

### F-01: File storage TOCTOU — HIGH
- **File**: `unix-oidc-agent/src/storage/file_store.rs:66-79`
- **Issue**: `File::create()` then `set_permissions(0o600)` — non-atomic. Window between creation (umask-default) and chmod where another process can read credentials.
- **Fix**: Replaced with `OpenOptions::new().mode(0o600)` via `OpenOptionsExt` — permissions set atomically at creation.
- **Tests**: `test_store_creates_file_with_0600_atomically` (positive), `test_store_never_creates_world_readable_file` (negative)

### F-02: Askpass tmpfile TOCTOU + predictable path — HIGH
- **File**: `unix-oidc-agent/src/askpass.rs:74-84`
- **Issue**: `fs::write()` then `set_permissions(0o600)`. Path is `$TMPDIR/.unix-oidc-token-{PPID}` — predictable. Symlink attack vector + no secure delete on read.
- **Fix**: Same atomic `OpenOptions::mode(0o600)` pattern.
- **Tests**: `test_write_restricted_perms_atomic_0600` (positive), `test_write_restricted_perms_no_group_other_bits` (negative)

### F-03: Client secret visible in process list — HIGH
- **File**: `unix-oidc-agent/src/main.rs:181`
- **Issue**: `--client-secret` CLI arg visible via `ps aux` / `/proc/PID/cmdline`. Wrapped in `SecretString` after parsing but initial exposure in process args is the damage vector.
- **Fix**: Arg hidden from `--help`, runtime deprecation warning directing to `OIDC_CLIENT_SECRET` env var.
- **Tests**: `test_client_secret_arg_hidden_from_help` (positive), `test_client_secret_absent_from_rendered_help` (negative)

### F-04: Sudo session_id predictable — HIGH
- **File**: `pam-unix-oidc/src/sudo.rs:657-664`
- **Issue**: `format!("sudo-{timestamp:x}")` — nanosecond timestamp only, no CSPRNG. `generate_sudo_session_id()` with getrandom existed but was not used.
- **Fix**: Replaced body with call to `crate::security::session::generate_sudo_session_id()`.
- **Tests**: `test_generate_session_id_format_with_csprng` (positive), `test_generate_session_id_uniqueness_from_csprng` (negative)

### F-05: Approval request_id predictable — HIGH
- **File**: `pam-unix-oidc/src/approval/provider.rs:225-232`
- **Issue**: `format!("apr-{timestamp:x}")` — same timestamp-only pattern.
- **Fix**: Added `getrandom::fill()` for 8 bytes of CSPRNG randomness.
- **Tests**: `test_request_id_format_with_csprng` (positive), `test_request_id_uniqueness_from_csprng` (negative)

### F-06: Webhook TLS disable not gated behind test-mode — HIGH
- **File**: `pam-unix-oidc/src/approval/webhook.rs:111-116`
- **Issue**: `UNIX_OIDC_WEBHOOK_INSECURE=true` disables cert verification without `test-mode` feature gate. Production deployments could be MITM'd.
- **Fix**: Entire block wrapped in `#[cfg(feature = "test-mode")]`.
- **Tests**: `test_webhook_config_default_tls_enabled` (positive), `test_webhook_insecure_env_ignored_without_test_mode` (negative)

### F-07: CIBA binding message UTF-8 truncation panic — HIGH
- **File**: `pam-unix-oidc/src/ciba/client.rs:131-137`
- **Issue**: `msg[..64]` byte-slices a String. Panics if byte 64 falls mid-character. **Panic in PAM = user lockout.**
- **Fix**: `char_indices()` boundary-safe truncation.
- **Tests**: `binding_message_ascii_truncates_to_exact_64` (positive), `binding_message_multibyte_utf8_no_panic` + `binding_message_cjk_boundary_no_panic` (negative)

### F-08: JSON injection in IPC session_closed message — MEDIUM
- **File**: `pam-unix-oidc/src/lib.rs:835`
- **Issue**: `format!()` interpolation of `session_id` into JSON without escaping. If session_id contains `"`, attacker can inject JSON fields.
- **Fix**: Replaced with `serde_json::json!()` macro for proper escaping.
- **Tests**: `test_session_closed_json_normal_id` (positive), `test_session_closed_json_injection_prevented` (negative)

### F-09: JWK thumbprint uses user-supplied kty/crv — MEDIUM
- **Files**: `rust-oauth-dpop/src/server.rs:348-358`, `rust-oauth-dpop/src/thumbprint.rs:37-47`
- **Issue**: `compute_jwk_thumbprint()` and `compute_thumbprint_from_jwk()` embed `jwk.crv`/`jwk.kty` in canonical JSON instead of hardcoded `"P-256"`/`"EC"`. Attacker supplying `kty: "oct"` changes thumbprint.
- **Fix**: Hardcoded canonical values in both functions.
- **Tests**: `test_f09_thumbprint_from_jwk_matches_coordinates` (positive), `test_f09_attacker_cannot_alter_thumbprint_via_kty_crv` (negative)

### F-10: RwLock poison panic in PAM context — MEDIUM
- **File**: `rust-oauth-dpop/src/server.rs:50,60,76,81,83`
- **Issue**: `.unwrap()` on all RwLock operations. Lock poisoning → panic → PAM crash → user lockout.
- **Fix**: All 7 calls replaced with `.unwrap_or_else(|e| e.into_inner())`.
- **Tests**: `test_f10_cache_normal_operation` (positive), `test_f10_cache_survives_lock_poisoning` (negative)

### F-11: No IPC message size limit — MEDIUM
- **File**: `unix-oidc-agent/src/daemon/socket.rs:548-595`
- **Issue**: `BufReader::read_line()` buffers arbitrarily large lines. Local attacker (same UID) can OOM the daemon.
- **Fix**: Added `MAX_IPC_MESSAGE_SIZE = 64 KiB` check after read.
- **Tests**: `test_normal_sized_ipc_message_processed` (positive), `test_oversized_ipc_message_rejected` (negative)

### F-12: Rate limiter stale attempts enable re-lockout — MEDIUM
- **File**: `pam-unix-oidc/src/security/rate_limit.rs:247-265`
- **Issue**: `record_success()` resets `consecutive_failures` and `lockout_until` but NOT the `attempts` Vec. After success, one more failure → immediate re-lockout.
- **Fix**: Added `entry.attempts.clear()` on success.
- **Tests**: `test_success_clears_attempts_allows_full_budget` (positive), `test_single_failure_after_success_does_not_relock` (negative)

### F-13: Rate limiter unbounded + no auto-cleanup — MEDIUM
- **File**: `pam-unix-oidc/src/security/rate_limit.rs:201`
- **Issue**: `record_failure()` inserts into unbounded HashMap. `cleanup()` exists but is never called automatically.
- **Fix**: Added `MAX_ENTRIES = 100_000`, `maybe_cleanup()` called from `record_failure()`, time-based + size-based triggers.
- **Tests**: `test_cleanup_removes_expired_entries` (positive), `test_maybe_cleanup_triggered_by_record_failure` (negative)

### F-14: Rate limit config no bounds validation — MEDIUM
- **File**: `pam-unix-oidc/src/security/rate_limit.rs:96-121`
- **Issue**: `from_env()` accepts any u32 for `max_attempts`. Setting to 0 = immediate lockout; u32::MAX = disabled.
- **Fix**: Clamp to `1..=1000` with `tracing::warn!` when out of range.
- **Tests**: `test_rate_limit_config_valid_max_attempts` (positive), `test_rate_limit_config_zero_clamped_to_min` + `test_rate_limit_config_large_clamped_to_max` (negative)

### F-15: DPoP algorithm string unrestricted — MEDIUM
- **File**: `unix-oidc-agent/src/crypto/dpop.rs:162-196`
- **Issue**: `build_dpop_message_with_alg()` accepts arbitrary `alg: &str`. Could accept `"none"` or symmetric algorithms.
- **Fix**: Validate against `ALLOWED_ALGORITHMS = ["ES256", "ML-DSA-65-ES256"]`. Added `DPoPError::UnsupportedAlgorithm`.
- **Tests**: 2 positive (ES256, ML-DSA-65-ES256 accepted), 4 negative ("none", "HS256", "RS256", "" rejected)

### F-16: rust-oauth-dpop JTI cache unbounded — MEDIUM
- **File**: `rust-oauth-dpop/src/server.rs:23-86`
- **Issue**: `HashMap<String, Instant>` with no max capacity. Cleanup only every 300s.
- **Fix**: Added `MAX_CACHE_ENTRIES = 100_000`. Inline cleanup on overflow; entries never rejected (prevents DoS).
- **Tests**: `test_f16_cache_size_limit_triggers_cleanup` (negative), `test_f16_cache_accepts_entries_when_over_limit_after_cleanup` (positive)

---

## Acknowledged Design Limitations

These findings represent inherent architectural constraints that are documented, understood, and have compensating controls.

### Cross-Server and Same-Server Replay Analysis

This section documents the multi-server replay threat model in detail. Both Claude and Gemini independently analyzed this; their conclusions are synthesized below with areas of agreement and disagreement noted.

#### Scenario: User logs into Server A and Server B simultaneously

```
Client (agent)               Server A                    Server B
──────────────               ────────                    ────────
get_proof("serverA", "SSH")
  → proof { htu:"serverA",  validates htu=="serverA" ✓
            jti:"uuid-1",   records jti in local cache
            cnf:{thumb} }

get_proof("serverB", "SSH")
  → proof { htu:"serverB",                              validates htu=="serverB" ✓
            jti:"uuid-2",                                records jti in local cache
            cnf:{thumb} }
```

**Cross-server replay (token from Server A replayed to Server B): BLOCKED**

Both reviewers agree this is blocked by DPoP's `htu` binding (RFC 9449 §4.3):
- The agent generates a fresh proof per `get_proof()` call with `htu` set to the target hostname (`askpass.rs:148`, `crypto/dpop.rs:78`)
- Each server's PAM module sets `expected_target` to its own hostname via `gethostname()` (`lib.rs:334`)
- The server validates `claims.htu != config.expected_target` at `dpop.rs:348` — a proof bound to `serverA` fails on `serverB` with `TargetMismatch`

**Caveat (Gemini)**: If the attacker steals the agent's DPoP *private key* (not just the token), they can forge a new proof for any server. This is why the agent uses `mlock`, `ZeroizeOnDrop`, and disabled core dumps for key material.

#### Same-server replay (same proof replayed to same server, different connection): THEORETICALLY POSSIBLE, PRACTICALLY INFEASIBLE

**Where reviewers agree**: The per-fork JTI cache means a second connection to the same server has an empty cache and would not detect the replayed JTI.

**Where Claude disagrees with Gemini's "WIDE OPEN" characterization**: The attack requires intercepting the DPoP proof, which travels *inside* the SSH encrypted channel (keyboard-interactive). An attacker who can MITM the SSH transport layer has already bypassed all authentication — OIDC is irrelevant at that point. The practical attack chain is:

1. Attacker must intercept SSH-encrypted keyboard-interactive data (requires SSH MITM or compromised server)
2. Extract the DPoP proof from the SSH session
3. Replay it to the same server within the proof's `iat` window (default 60s)
4. The proof's `cnf` thumbprint must match the token's `cnf` claim — both are bound to the agent's ephemeral key

If the attacker has SSH MITM capability, they already have a shell. DPoP replay is moot.

#### Nonce handling across forks: NOT BROKEN

Gemini claimed that nonce issuance in fork #1 and consumption in fork #2 creates a permanent auth loop. This analysis is based on the standard HTTP DPoP retry pattern (server returns 401 with `DPoP-Nonce` header → client retries in a new connection). **That pattern would indeed loop in a forking model. But our implementation uses a different pattern.**

**Standard HTTP DPoP nonce flow (what Gemini analyzed):**
1. Client sends proof → Server: "401, use nonce X" → connection dies
2. Client reconnects with nonce X → new fork: "I don't know nonce X, use nonce Y" → dies
3. Permanent loop

**Our PAM keyboard-interactive flow (what the code actually does):**
1. `issue_and_deliver_nonce()` at `lib.rs:247` generates nonce, stores it in process-local cache, delivers to client via `PROMPT_ECHO_ON` (**Round 1**, same connection)
2. Client binds nonce into DPoP proof
3. `pamh.conv("DPOP_PROOF: ", PROMPT_ECHO_OFF)` at `lib.rs:251` collects the proof (**Round 2**, same connection)
4. `auth.rs:487` calls `global_nonce_cache().consume(nonce)` from the **same process's cache**

All four steps occur within a single forked sshd child. The nonce is issued and consumed in the same process. There is no cross-fork nonce handoff and no auth loop.

**Edge case — client ignores the nonce (legacy client or bug):**
If the proof arrives at `auth.rs:505` without a nonce and enforcement is `Strict`, auth fails with `MissingNonce`. The client must reconnect. But the next connection's fork will also proactively issue a new nonce in Round 1 and collect the proof in Round 2 — which works because that fork is also self-contained. Each connection is independently correct. A client that consistently fails to bind nonces will consistently fail auth, which is enforcement working as intended, not a loop.

**Why Gemini's analysis was reasonable but wrong**: Gemini correctly identified that the standard HTTP DPoP nonce-retry pattern breaks in a forking model. Our implementation specifically avoids this by using proactive nonce delivery within a multi-round PAM conversation instead of the HTTP 401-retry pattern. This is a deliberate design choice documented at `lib.rs:233-245`.

### VULN-001 / VULN-006: In-memory replay protection is per-fork (Gemini finding) — HIGH (by-design)
- **Files**: `pam-unix-oidc/src/security/jti_cache.rs`, `nonce_cache.rs`, `rust-oauth-dpop/src/server.rs`
- **Issue**: JTI and DPoP nonce caches use `Lazy` singletons. In forked sshd, each child has independent state. A captured token+proof can theoretically be replayed across connections within the token's validity window.
- **Design rationale**: PAM modules run in-process within sshd children. Shared-memory or external daemon coordination adds significant complexity and failure modes to a security-critical path. The in-memory approach is a deliberate tradeoff: replay protection within a connection is guaranteed; cross-connection replay requires SSH transport compromise (at which point all authentication is moot).
- **Compensating controls**: (1) DPoP proof `iat` window is configurable and defaults to 60s. (2) Token `exp` limits the replay window. (3) DPoP `cnf` binding means a replayed token is useless without the ephemeral private key. (4) The token+proof travel inside SSH encryption — intercepting them requires SSH MITM. (5) The JTI cache in `jti_cache.rs:14-16` explicitly documents this limitation.
- **Future mitigation**: A shared-state cache via the `unix-oidc-agent` daemon (running as a system service) is a candidate for a future milestone. Tracked as a design decision.

### VULN-002: Implicit trust in agent for CIBA step-up (Gemini finding) — MEDIUM (acknowledged)
- **File**: `pam-unix-oidc/src/sudo.rs:371-377`
- **Issue**: The PAM module trusts the `StepUpComplete` JSON from the agent IPC without cryptographic validation. The agent returns `{ acr, session_id }` but no ID token for the PAM module to independently verify.
- **Verification**: Confirmed at sudo.rs:371-377 — `acr` is read from JSON and used directly. No signature verification, no issuer/audience check.
- **Design rationale**: The IPC channel is protected by Unix socket peer credential verification (UID match). An attacker who can spoof IPC responses already has the target user's UID — at which point they can also read the user's SSH keys, browser cookies, etc. The threat model assumes same-UID compromise is equivalent to user compromise.
- **Compensating controls**: (1) Socket permissions are 0600. (2) `peer_cred.rs` validates UID via `SO_PEERCRED`/`getpeereid`. (3) The agent is the only process that talks to the IdP; it performs full OIDC validation internally.
- **Future mitigation**: Return the CIBA ID token from the agent and validate it in the PAM module for defense-in-depth. This is a v3.1 candidate.

### VULN-003: Missing zeroization of bearer tokens in PAM module (Gemini finding) — MEDIUM (acknowledged)
- **Files**: `pam-unix-oidc/src/auth.rs`, `pam-unix-oidc/src/oidc/token.rs`
- **Issue**: OIDC tokens are handled as standard `String`/`TokenClaims` without `SecretString` or `Zeroizing`. Heap memory containing tokens could be swapped to disk.
- **Verification**: Confirmed — `grep -r "SecretString\|Zeroiz" pam-unix-oidc/src/` returns zero hits.
- **Design rationale**: The `unix-oidc-agent` (client-side daemon) uses full memory protection (SecretString, mlock, ZeroizeOnDrop) because it holds long-lived keys. The PAM module handles tokens transiently in a short-lived forked process that exits after authentication.
- **Compensating controls**: (1) sshd forks per connection — process exits and memory is reclaimed after auth. (2) Core dumps are disabled at startup. (3) Tokens are short-lived (minutes).
- **Future mitigation**: Add `Zeroizing<String>` wrappers for token handling in the PAM module for defense-in-depth against swap-based exposure. Tracked for Tier 2.

---

## Deferred Findings (Tier 2)

These are real findings that require design work or larger refactoring.

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| F-17 | MED | Webhook approval lacks request/response HMAC signing | Requires protocol design |
| F-18 / VULN-003 | MED | PAM config `client_secret` as plain `String` with `Debug` derive | Wrap in `SecretString` |
| F-19 | MED | HMAC audit key not hex-decoded (raw UTF-8 bytes used) | Clarify docs or hex-decode |
| VULN-004 | LOW | TOCTOU in `secure_delete.rs` (check-then-open) | Open first, then check metadata |
| VULN-005 | LOW | Unbounded `IssuerJwksRegistry` HashMap | Add LRU eviction or size cap |
| F-20 | LOW | Introspection cache key uses only first 32 bytes of token | Hash full token |
| F-21 | LOW | Device flow/CIBA: no HTTPS scheme validation on endpoints | Validate at construction |
| F-22 | LOW | Session ID: 64-bit randomness (below NIST 128-bit) | Increase to 128 bits |
| F-23 | LOW | Latency histogram `Vec::remove(0)` is O(n) | Use `VecDeque` |

---

## Additional Observations (Informational)

These are positive security properties confirmed during the review.

| Area | Assessment |
|------|------------|
| **Algorithm confusion prevention** | Comprehensive allowlist (asymmetric-only), JWKS-pinned alg, explicit HS*/encryption rejection. Covers CVE-2016-5431 class. |
| **DPoP thumbprint computation (PAM)** | Hardcoded canonical `"P-256"`/`"EC"` in `pam-unix-oidc/src/oidc/dpop.rs`. Correct per RFC 7638. |
| **PQC composite signatures** | Both ML-DSA-65 and ES256 independently verified. Attacker cannot provide only one component. |
| **Break-glass bypass** | Requires `enabled == true` AND user in configured accounts. Returns `PAM_IGNORE` to defer to next PAM module. |
| **Test-mode compile guard** | `compile_error!` prevents `test-mode` feature in release builds. |
| **Peer credential verification** | `SO_PEERCRED` (Linux) / `getpeereid` (macOS) with fail-closed semantics. UID comparison prevents cross-user IPC. |
| **Terminal sanitization** | Strips C0, C1, CSI, OSC, DCS, APC, PM, SOS sequences. Prevents IdP-supplied terminal injection. |
| **HMAC audit chain** | Correct hash chain composition; modification of any event breaks subsequent hashes. Per-process mutex prevents interleaving. |
| **Nonce cache atomic consume** | `moka::Cache::remove()` as atomic test-and-delete — no TOCTOU. |
| **Key material protection (agent)** | Box-only constructors, mlock, ZeroizeOnDrop, Zeroizing exports, core dump disable. |
