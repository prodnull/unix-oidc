---
phase: 01-memory-protection-hardening
verified: 2026-03-10T15:00:00Z
status: passed
score: 6/6 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 5/6
  gaps_closed:
    - "refresh_token wrapped in SecretString at extraction in main.rs (run_refresh) and socket.rs (perform_token_refresh)"
    - "client_secret wrapped in SecretString at extraction in main.rs (run_login, run_refresh) and socket.rs (perform_token_refresh)"
    - "expose_secret() confined to HTTP param boundaries and storage write points only — no raw String intermediates"
    - "REQUIREMENTS.md traceability table: MEM-03 row updated from Pending to Complete"
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Start agent with RUST_LOG=debug, perform login and refresh, grep logs for raw token values"
    expected: "No raw access_token, refresh_token, or client_secret values appear in logs at any level"
    why_human: "Requires a live IdP or mock server and an active tracing subscriber to produce log output"
  - test: "Run unix-oidc-agent serve on a Linux host as non-root with default RLIMIT_MEMLOCK, then check unix-oidc-agent status output"
    expected: "Output includes either mlock active confirmation or EPERM advisory with guidance text"
    why_human: "mlock probe outcome is environment-dependent; CI RLIMIT may differ from production"
  - test: "Login, logout, then inspect freed storage directory blocks with strings or a hex editor before OS reuse"
    expected: "No recoverable DPoP key bytes in freed blocks (three-pass overwrite was effective)"
    why_human: "Requires forensic disk inspection of deallocated blocks; grep cannot read freed storage"
---

# Phase 1: Memory Protection Hardening Verification Report

**Phase Goal:** Key material is zeroized on drop, locked against swap exposure, and wiped from disk with overwrite semantics
**Verified:** 2026-03-10T15:00:00Z
**Status:** passed
**Re-verification:** Yes — after MEM-03 gap closure (plan 01-04)

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | When `SigningKey` is dropped, key bytes are zeroed in memory | VERIFIED | `ecdsa-0.16` implements `ZeroizeOnDrop` unconditionally; `test_key_material_zeroed_after_drop` in `protected_key.rs` verifies zeroing via pointer inspection after drop |
| 2 | Daemon startup calls process hardening and logs mlock outcome at INFO | VERIFIED | `main.rs:158` calls `disable_core_dumps()`; `main.rs:162-173` calls `mlock_probe()`, formats result, logs at INFO, stores in `AgentState.mlock_status` |
| 3 | OAuth token printed via `{:?}` appears as `[REDACTED]` — all three credential types | VERIFIED | `access_token` is `SecretString` in `AgentState` with manual Debug impl emitting `[REDACTED]`. `refresh_token` is `SecretString` at extraction in `run_refresh` (main.rs:606) and `perform_token_refresh` (socket.rs:415). `client_secret` is `Option<SecretString>` at extraction in `run_login` (main.rs:308), `run_refresh` (main.rs:625), and `perform_token_refresh` (socket.rs:434). No raw String intermediate in any of the three functions. |
| 4 | File deletion performs random-overwrite + fsync + unlink; CoW advisory logged on btrfs/APFS | VERIFIED | `secure_delete.rs` implements three-pass DoD 5220.22-M overwrite; `file_store.rs::delete()` calls `secure_remove()`; CoW advisory logged at construction and per-delete |
| 5 | Memory protection rationale is present in CLAUDE.md and README security sections | VERIFIED | CLAUDE.md has "Memory Protection Invariants" section with 9 numbered invariants; README.md has "Security Design" section with memory/disk protection tables and NIST SP 800-88 Rev 1 reference |

**Score:** 5/5 truths fully verified

### Required Artifacts (Plan 01-04 focus — gap closure artifacts)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/main.rs` | SecretString wrapping for refresh_token and client_secret | VERIFIED | `run_login` line 308: `client_secret` wrapped as `Option<SecretString>` at extraction. `run_refresh` line 606: `refresh_token` wrapped as `SecretString::from(...)`. Line 625: `client_secret` wrapped as `Option<SecretString>`. All three expose_secret() calls are at HTTP param or storage write boundaries only. |
| `unix-oidc-agent/src/daemon/socket.rs` | SecretString wrapping for refresh_token and client_secret in perform_token_refresh | VERIFIED | Line 415: `refresh_token` wrapped as `SecretString::from(...)`. Line 434: `client_secret` wrapped as `Option<SecretString>`. expose_secret() at lines 448, 458, 510, 528 — all at HTTP param boundary or storage/username-extraction audit points. |
| `.planning/REQUIREMENTS.md` | MEM-03 traceability shows Complete | VERIFIED | Checklist at line 14: `[x] MEM-03`. Traceability table at line 77: `MEM-03 | Phase 1 | Complete`. Commit `ff52d54` corrected the table from Pending. |

### Full Artifact Status (All Plans)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/crypto/protected_key.rs` | ProtectedSigningKey with ZeroizeOnDrop, mlock, Box-only constructors | VERIFIED | 399 lines; `generate() -> Box<Self>`, `from_bytes() -> Result<Box<Self>, _>`, no public stack constructor; `MlockGuard` RAII; `export_key() -> Zeroizing<Vec<u8>>`; 8 tests |
| `unix-oidc-agent/Cargo.toml` | zeroize, secrecy, libc dependencies | VERIFIED | `zeroize = { version = "1", features = ["derive"] }`, `secrecy = "0.10"`, `libc = "0.2"` present |
| `unix-oidc-agent/src/crypto/signer.rs` | SoftwareSigner uses ProtectedSigningKey internally | VERIFIED | `key: Box<ProtectedSigningKey>`; `export_key() -> Zeroizing<Vec<u8>>` |
| `unix-oidc-agent/src/security.rs` | disable_core_dumps with prctl/PT_DENY_ATTACH | VERIFIED | `prctl(PR_SET_DUMPABLE, 0)` on Linux; `ptrace(PT_DENY_ATTACH, 0, null, 0)` on macOS; best-effort WARN on failure |
| `unix-oidc-agent/src/daemon/socket.rs` | AgentState with SecretString access_token; perform_token_refresh wraps refresh_token and client_secret | VERIFIED | `access_token: Option<SecretString>` with manual Debug impl. `perform_token_refresh` wraps all three credential types. |
| `unix-oidc-agent/src/storage/secure_delete.rs` | Three-pass secure delete, CoW detection, SSD detection | VERIFIED | 355 lines; three-pass `overwrite_three_pass()` (random, complement, random); btrfs/APFS CoW detection; `/sys/block` rotational check; 7 tests |
| `unix-oidc-agent/src/storage/file_store.rs` | FileStorage::delete uses secure_delete | VERIFIED | `delete()` calls `secure_delete::secure_remove()`; `new()` calls `log_storage_advisories()` |
| `CLAUDE.md` | Memory Protection security invariants | VERIFIED | "Memory Protection Invariants" section with mlock, ZeroizeOnDrop, zeroize, prctl, CoW filesystem content |
| `README.md` | Memory protection documentation | VERIFIED | "Security Design" section with zeroize, mlock, PR_SET_DUMPABLE; NIST SP 800-88 Rev 1 reference |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `protected_key.rs` | `p256::ecdsa::SigningKey` | ZeroizeOnDrop derive | WIRED | `signing_key: SigningKey` field; ecdsa-0.16 unconditional ZeroizeOnDrop |
| `signer.rs` | `protected_key.rs` | `ProtectedSigningKey` field | WIRED | `key: Box<ProtectedSigningKey>` |
| `main.rs` | `security::disable_core_dumps` | called before key load | WIRED | Line 158 before `load_agent_state()` |
| `main.rs` | `protected_key::mlock_probe` | called at daemon startup | WIRED | Line 162; result stored in `AgentState.mlock_status` |
| `main.rs::run_login` | `secrecy::SecretString` | client_secret wrapped at extraction | WIRED | Line 308: `let client_secret: Option<SecretString> = client_secret.map(SecretString::from).or_else(...)` |
| `main.rs::run_refresh` | `secrecy::SecretString` | refresh_token wrapped at extraction | WIRED | Line 606: `let refresh_token = SecretString::from(metadata["refresh_token"]...)` |
| `main.rs::run_refresh` | `secrecy::SecretString` | client_secret wrapped at extraction | WIRED | Line 625: `let client_secret: Option<SecretString> = metadata["client_secret"].as_str().map(...)` |
| `socket.rs::perform_token_refresh` | `secrecy::SecretString` | refresh_token wrapped at extraction | WIRED | Line 415: `let refresh_token = SecretString::from(metadata["refresh_token"]...)` |
| `socket.rs::perform_token_refresh` | `secrecy::SecretString` | client_secret wrapped at extraction | WIRED | Line 434: `let client_secret: Option<SecretString> = metadata["client_secret"].as_str().map(...)` |
| `main.rs` | `expose_secret()` | HTTP params and storage write only | WIRED | 7 call sites: lines 371, 460, 536, 546, 641, 651, 701 — all at HTTP form params or storage write boundaries |
| `socket.rs` | `expose_secret()` | HTTP params and storage write only | WIRED | 4 call sites: lines 215, 448, 458, 510, 528 — HTTP params, storage write, username extraction (non-sensitive) |
| `file_store.rs` | `secure_delete.rs` | `delete()` calls `secure_remove()` | WIRED | Direct call; `log_storage_advisories` at construction |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| MEM-01 | 01-01, 01-02 | All key export paths return `Zeroizing<Vec<u8>>` instead of raw `Vec<u8>` | SATISFIED | `protected_key.rs::export_key()` and `signer.rs::export_key()` return `Zeroizing<Vec<u8>>`; test `test_export_key_returns_zeroizing` verifies type |
| MEM-02 | 01-01 | p256 built with zeroize feature enabling ZeroizeOnDrop on SigningKey | SATISFIED | ZeroizeOnDrop unconditional in ecdsa-0.16 (no feature flag required); `test_key_material_zeroed_after_drop` verifies zeroing behavior |
| MEM-03 | 01-02, 01-04 | In-memory OAuth tokens wrapped in Secret<String> (access token, refresh token, client secret) | SATISFIED | All three credential types are SecretString: access_token in AgentState (plan 01-02); refresh_token and client_secret in run_login, run_refresh, perform_token_refresh (plan 01-04, commit 4de0359). REQUIREMENTS.md traceability table corrected to Complete (commit ff52d54). |
| MEM-04 | 01-01 | Key material pages locked via mlock with best-effort semantics | SATISFIED | `try_mlock()` in `protected_key.rs::new_inner()` locks the Box allocation; EPERM/ENOMEM logged as WARN; never fatal |
| MEM-05 | 01-01, 01-03 | Key material on heap only, no stack copies across function boundaries | SATISFIED | No public `new() -> Self` constructor on ProtectedSigningKey; `from_key(SigningKey)` round-trips through Zeroizing bytes |
| MEM-06 | 01-03 | Documentation updated with memory protection design rationale and limitations | SATISFIED | CLAUDE.md "Memory Protection Invariants" section; README.md "Security Design" section with tables and NIST SP 800-88 Rev 1 reference |

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `main.rs:696-710` | `new_refresh_token` extracted as `&str` from serde_json::Value for JSON storage roundtrip | Info | Intentional design: Value -> Value -> storage bytes; no intermediate plain String variable; documented in SUMMARY as transient JSON pattern |
| `main.rs:786` | `mlock_status: None` hardcoded in `load_agent_state()` AgentState construction | Info | Benign: status correctly set in `run_serve()` after probe; this is pre-serve state |

No TODO/FIXME/placeholder patterns found in implementation files. No empty return stubs. No raw String intermediates for refresh_token or client_secret in any of the four previously-flagged code locations.

### Human Verification Required

#### 1. End-to-End Token Redaction Under Tracing

**Test:** Start the agent with `RUST_LOG=debug`, perform a login and a token refresh, then grep the captured log output for the raw token values.
**Expected:** No raw access_token, refresh_token, or client_secret values appear in logs at any level. All three credential types should appear only as `[REDACTED]` if logged as part of a struct.
**Why human:** Requires a live IdP or mock and an active tracing subscriber to produce log output.

#### 2. mlock Active Status on Production Linux

**Test:** Run `unix-oidc-agent serve` on a Linux host as a non-root user with default RLIMIT_MEMLOCK, then run `unix-oidc-agent status`.
**Expected:** Output includes either "Memory protection: mlock active: key pages memory-locked" or "Memory protection: mlock unavailable: EPERM (...)" with guidance text.
**Why human:** mlock probe outcome is environment-dependent; CI environment may have different RLIMIT settings than production.

#### 3. Secure Delete Overwrite Confirmation on Non-CoW Filesystem

**Test:** Login, logout, then use `strings` or a hex editor on the free blocks of the storage directory before the OS reuses them, looking for the DPoP key bytes.
**Expected:** No recoverable key material in freed blocks.
**Why human:** Requires forensic disk inspection of deallocated blocks; grep cannot read freed storage.

### Gaps Summary

No gaps remain. The single gap from the initial verification — `refresh_token` and `client_secret` held as raw `String` in three functions — has been fully resolved by plan 01-04 (commit `4de0359`). All six MEM-0x requirements are satisfied. The REQUIREMENTS.md traceability table is now consistent with the checklist (commit `ff52d54`).

---

_Verified: 2026-03-10T15:00:00Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification: Yes — initial verification 2026-03-10T14:00:00Z had status gaps_found (5/6)_
