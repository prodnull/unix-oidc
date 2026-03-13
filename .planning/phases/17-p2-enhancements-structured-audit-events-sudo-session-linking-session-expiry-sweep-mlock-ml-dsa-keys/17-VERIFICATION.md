---
phase: 17-p2-enhancements
verified: 2026-03-13T05:30:00Z
status: passed
score: 10/10 must-haves verified
re_verification: false
---

# Phase 17: P2 Enhancements Verification Report

**Phase Goal:** Deliver four P2 enhancements: structured audit events (OBS-1), sudo session linking (OBS-3), session expiry sweep (SES-09), mlock ML-DSA key material (MEM-07)
**Verified:** 2026-03-13T05:30:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `HybridPqcSigner::generate()` returns `Box<Self>`, not `Self` | VERIFIED | `pqc_signer.rs` line 130: `pub fn generate() -> Box<Self>` |
| 2 | ML-DSA-65 key material is mlock'd on supported platforms (best-effort) | VERIFIED | `new_inner()` calls `try_mlock(struct_bytes)` over full Box allocation; debug log on success/skip |
| 3 | ML-DSA key bytes are zeroed on drop (ZeroizeOnDrop) | VERIFIED | `test_ml_dsa_zeroize_on_drop` uses `drop_in_place` + raw pointer read; `pq_seed` field verified |
| 4 | Expired session records in `/run/unix-oidc/sessions/` are automatically removed within the sweep interval | VERIFIED | `sweep.rs` `session_expiry_sweep_loop` spawned from `serve_with_listener`; wired in `main.rs` with 300s default |
| 5 | Corrupt/unparseable session files are removed with a warning | VERIFIED | `sweep_expired_sessions` removes files where `token_exp` parse fails; `warn!` emitted |
| 6 | Concurrent delete by PAM (ENOENT) is handled gracefully | VERIFIED | `remove_session_file` matches `ErrorKind::NotFound` and treats it as success |
| 7 | Sweep interval is configurable via config file (default 300s) | VERIFIED | `TimeoutsConfig.sweep_interval_secs` defaults to 300 via `default_sweep_interval()`; env override `UNIX_OIDC_TIMEOUTS__SWEEP_INTERVAL_SECS` tested |
| 8 | Agent emits structured audit events with target `unix_oidc_audit` at all five event types | VERIFIED | 9 `tracing::info!(target: "unix_oidc_audit", ...)` calls confirmed in `socket.rs` across GetProof (4), spawn_refresh_task (1), SessionClosed (1), StepUp (1), StepUpResult (2) |
| 9 | Every audit event includes `event_type`, `session_id`, `username`, and `outcome` fields | VERIFIED | All 9 audit events grep-confirmed to include all four required fields |
| 10 | `parent_session_id` flows from PAM sudo through StepUp IPC to StepUpComplete response | VERIFIED | `sudo.rs` reads `UNIX_OIDC_SESSION_ID`; `AgentRequest::StepUp`, `PendingStepUp`, `StepUpOutcome::Complete`, `AgentResponseData::StepUpComplete` all carry the field |

**Score:** 10/10 truths verified

---

## Required Artifacts

### Plan 01 (MEM-07)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/crypto/pqc_signer.rs` | Box-only HybridPqcSigner with mlock + zeroize | VERIFIED | `new_inner() -> Box<Self>`, `_mlock_guard: Option<MlockGuard>` field, `MlockGuard` imported from `protected_key` via `pub(crate)` |
| `unix-oidc-agent/src/crypto/protected_key.rs` | `MlockGuard` and `try_mlock` promoted to `pub(crate)` | VERIFIED | Both declared `pub(crate)` at lines 47 and 120 |
| `unix-oidc-agent/src/main.rs` | Updated call sites for `Box<HybridPqcSigner>` | VERIFIED | `sweep_interval_secs` captured; `Arc::new(*pqc)` dereferences Box at call sites |

### Plan 02 (SES-09)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/daemon/sweep.rs` | Session expiry sweep background task | VERIFIED | File exists; contains `session_expiry_sweep_loop` and `sweep_expired_sessions`; 9 unit tests |
| `unix-oidc-agent/src/config.rs` | `sweep_interval_secs` in `TimeoutsConfig` | VERIFIED | Field present with `#[serde(default = "default_sweep_interval")]`; default is 300; min validation 60 |
| `unix-oidc-agent/src/daemon/mod.rs` | `pub mod sweep;` registration | VERIFIED | Line 11: `pub mod sweep;` |
| `unix-oidc-agent/src/daemon/socket.rs` | `sweep_interval`/`session_dir` fields + spawn in `serve_with_listener` | VERIFIED | Builder fields present; `tokio::spawn(sweep::session_expiry_sweep_loop(...))` in `serve_with_listener` |
| `unix-oidc-agent/src/main.rs` | Wires sweep config from `AgentConfig` | VERIFIED | `sweep_interval_secs` captured; `.with_sweep_interval(...)` and `.with_session_dir(...)` in builder chain |

### Plan 03 (OBS-1, OBS-3)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/daemon/protocol.rs` | `parent_session_id` on `StepUp` and `StepUpComplete` | VERIFIED | Both variants have `#[serde(skip_serializing_if = "Option::is_none", default)] parent_session_id: Option<String>`; 5 serde tests added |
| `unix-oidc-agent/src/daemon/socket.rs` | 9 audit event emission points with `target: "unix_oidc_audit"` | VERIFIED | grep confirms 9 occurrences of `target: "unix_oidc_audit"` across all required event types |
| `pam-unix-oidc/src/sudo.rs` | `parent_session_id` read from `UNIX_OIDC_SESSION_ID` and included in StepUp IPC | VERIFIED | `std::env::var("UNIX_OIDC_SESSION_ID")` read; conditionally appended to StepUp JSON |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `pqc_signer.rs` | `libc::mlock` | `try_mlock` helper from `protected_key` | WIRED | `unsafe { try_mlock(struct_bytes) }` called in `new_inner()` |
| `socket.rs` | `daemon/sweep.rs` | `tokio::spawn` in `serve_with_listener` | WIRED | `tokio::spawn(async move { crate::daemon::sweep::session_expiry_sweep_loop(sweep_dir, interval).await; })` |
| `sweep.rs` | `/run/unix-oidc/sessions/*.json` | `std::fs::read_dir` + `serde_json::Value` parse + `remove_file` | WIRED | `read_dir(session_dir)` → iterate `.json` entries → parse as `serde_json::Value` → `remove_session_file` |
| `pam-unix-oidc/src/sudo.rs` | `unix-oidc-agent/src/daemon/protocol.rs` | `StepUp` IPC message with `parent_session_id` | WIRED | Field conditionally appended to JSON; backward-compat serde on agent side |
| `socket.rs` | `tracing` | `target: "unix_oidc_audit"` events | WIRED | 9 `tracing::info!(target: "unix_oidc_audit", ...)` calls confirmed |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| MEM-07 | 17-01 | ML-DSA-65 key material mlock'd in HybridPqcSigner via Box-only constructors | SATISFIED | `new_inner() -> Box<Self>` with `try_mlock`; `_mlock_guard` field; commit `0d28603` |
| SES-09 | 17-02 | Background session expiry sweep in agent daemon (default 300s) | SATISFIED | `sweep.rs` created; wired via `serve_with_listener`; 9 tests; commits `3c46f93`, `05de55a` |
| OBS-1 | 17-03 | Agent-side structured audit events with required fields | SATISFIED | 9 emission points in `socket.rs` with `event_type`, `session_id`, `username`, `outcome`; commit `ab4e3d1` |
| OBS-3 | 17-03 | Sudo step-up session linking via `parent_session_id` | SATISFIED | Field threaded through `sudo.rs` → `StepUp` IPC → `PendingStepUp` → `StepUpOutcome::Complete` → `StepUpComplete` response; commit `ffdff1e` |

**Orphaned requirements:** None. All four requirement IDs declared in PLAN frontmatter are accounted for and satisfied. REQUIREMENTS.md maps OBS-1, OBS-3, SES-09, MEM-07 to Phase 17 — all verified.

---

## Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| None found | — | — | — |

Scanned: `pqc_signer.rs`, `sweep.rs`, `protocol.rs`, `socket.rs` (audit event regions), `sudo.rs`, `config.rs`, `main.rs`.

No TODO/FIXME/PLACEHOLDER comments. No empty implementations. No stub return values in critical paths. No console.log-only handlers.

---

## Human Verification Required

The following items cannot be verified programmatically:

### 1. mlock Success on Production Linux

**Test:** Run the agent daemon on a production Linux host (not a container with EPERM), log at DEBUG level, and confirm `HybridPqcSigner mlock'd successfully` appears in logs when `--features pqc` is active.
**Expected:** Debug log confirms mlock succeeded; `mlockall`/`mlock` not returning EPERM on the target kernel.
**Why human:** mlock success depends on kernel limits (`RLIMIT_MEMLOCK`), container/VM configuration, and the platform. CI runs in containers where EPERM is expected; production behavior differs.

### 2. SIEM Integration — JSON Audit Log Format

**Test:** Start the agent with `RUST_LOG=unix_oidc_audit=info` and a `tracing-subscriber` JSON layer (as configured in `main.rs`). Perform a login, token refresh, and session close. Examine the JSON log lines emitted to stdout/syslog.
**Expected:** Each event line is valid JSON with `event_type`, `session_id`, `username`, `outcome`, and an automatic `timestamp` field from the JSON layer. No duplicate `timestamp` fields.
**Why human:** tracing-subscriber JSON layer behavior (field ordering, timestamp format) and SIEM parser compatibility require live execution to validate end-to-end.

### 3. Session Sweep on Live `/run/unix-oidc/sessions/`

**Test:** Start the agent daemon, create an SSH session, kill sshd without a clean close, wait 300s (or set `UNIX_OIDC_TIMEOUTS__SWEEP_INTERVAL_SECS=60` for faster test). Confirm the orphaned session file is removed.
**Expected:** Expired session file is removed; `Session sweep: removed session file (reason: expired)` appears in DEBUG logs.
**Why human:** Requires a live system with real PAM session lifecycle; cannot be unit-tested without process-level orchestration.

### 4. sudo Session Linking — End-to-End SIEM Correlation

**Test:** SSH into a server with unix-oidc PAM active. Run `sudo` to trigger a step-up. In SIEM logs, confirm `AGENT_STEP_UP` and `AGENT_STEP_UP_COMPLETE` events both carry the same `parent_session_id` matching the SSH session's `UNIX_OIDC_SESSION_ID`.
**Expected:** Both step-up audit events reference the parent SSH session; PAM environ variable is correctly inherited into the sudo PAM context on the target distro/sshd configuration.
**Why human:** PAM environ inheritance (`pam_putenv`/`std::env::var`) in sudo contexts varies by distro and sshd configuration. Cannot simulate this in unit tests.

---

## Gaps Summary

None. All phase goals are achieved:

- **MEM-07**: `HybridPqcSigner` is Box-only, mlock'd, ZeroizeOnDrop-verified, with `MlockGuard`/`try_mlock` shared from `protected_key.rs`. Four new tests. Commit `0d28603`.
- **SES-09**: `sweep.rs` created with `session_expiry_sweep_loop` and `sweep_expired_sessions`. Config field `sweep_interval_secs` defaults to 300 with minimum 60. Spawned from `serve_with_listener`; wired in `main.rs`. Nine unit tests covering all behavioral requirements. Commits `3c46f93`, `05de55a`.
- **OBS-1**: Nine `tracing::info!(target: "unix_oidc_audit", ...)` emission points in `socket.rs` covering all five logical event types (authentication success/failure, token refresh, session close, step-up initiated, step-up complete/timed-out). Every event includes `event_type`, `session_id`, `username`, `outcome`. Commit `ab4e3d1`.
- **OBS-3**: `parent_session_id` added to `AgentRequest::StepUp`, `PendingStepUp`, `StepUpOutcome::Complete`, `AgentResponseData::StepUpComplete`. PAM `sudo.rs` reads `UNIX_OIDC_SESSION_ID` and threads it through the entire IPC flow. Backward-compatible serde (`#[serde(default)]`). Five serde round-trip tests. Commit `ffdff1e`.

All six phase commits confirmed present in git history. REQUIREMENTS.md marks all four IDs as checked.

---

_Verified: 2026-03-13T05:30:00Z_
_Verifier: Claude (gsd-verifier)_
