---
phase: 10-ciba-step-up-fido2-acr-delegation
plan: "03"
subsystem: ciba-step-up
tags: [ciba, step-up, ipc, async, pam, sudo, dpop]
dependency_graph:
  requires: [10-01, 10-02]
  provides: [end-to-end CIBA step-up flow from PAM to IdP]
  affects: [unix-oidc-agent/src/daemon/socket.rs, pam-unix-oidc/src/sudo.rs]
tech_stack:
  added: []
  patterns:
    - "Tokio JoinHandle for async CIBA poll loop stored in AgentState HashMap"
    - "PAM-side short IPC poll loop (2s socket timeout per call) bounded by requirements.timeout"
    - "SecretString (MEM-03) wraps oidc_client_secret at extraction from KEY_TOKEN_METADATA"
    - "pub(crate) visibility on StepUpResult to satisfy Rust private_interfaces lint"
key_files:
  created: []
  modified:
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/main.rs
    - pam-unix-oidc/src/sudo.rs
    - pam-unix-oidc/src/policy/config.rs
decisions:
  - "PAM IPC pattern: short 2s-timeout blocking calls per poll cycle; CIBA 120s loop runs in agent Tokio runtime — avoids SSH LoginGraceTime race"
  - "challenge_timeout default raised from 60s to 120s (STP-07) to accommodate typical CIBA push notification round-trip"
  - "StepUpResult.jti is retained for future use but suppressed with #[allow(dead_code)] — device flow provides JTI; CIBA does not expose it at PAM layer"
  - "login_hint uses Unix username directly; IdP must be configured to accept username-based login_hint (config enhancement deferred per RESEARCH.md Open Question #1)"
  - "perform_step_up_via_ipc is pub(crate) to allow test access while keeping StepUpResult module-coherent"
metrics:
  duration_minutes: 90
  completed: "2026-03-11"
  tasks_completed: 2
  files_modified: 4
---

# Phase 10 Plan 03: CIBA Step-Up End-to-End Wiring Summary

End-to-end CIBA step-up flow: agent daemon handles StepUp IPC via CIBA backchannel auth and async poll loop; PAM sudo.rs routes Push/Fido2 to agent IPC with bounded blocking poll.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Agent daemon CIBA step-up handler with async poll loop | 6dc3b40 | daemon/socket.rs, main.rs |
| 2 | Wire CIBA step-up path in PAM sudo.rs | 949df9a | sudo.rs, policy/config.rs |

## What Was Built

### Task 1: Agent Daemon CIBA Step-Up Handler

**`unix-oidc-agent/src/daemon/socket.rs`** received the bulk of new functionality:

- `AgentState` extended with `oidc_issuer`, `oidc_client_id`, `oidc_client_secret` (SecretString, MEM-03), and `pending_step_ups: HashMap<String, PendingStepUp>`.
- `PendingStepUp` struct holds a Tokio `JoinHandle<StepUpOutcome>`, username, and expires_at instant.
- `StepUpOutcome` enum: `Complete { acr, session_id }` and `TimedOut { reason, user_message }`.
- `handle_step_up()`: validates OIDC config present, guards concurrent same-user step-up, fetches OIDC discovery, constructs `CibaClient`, POSTs backchannel auth request, spawns `poll_ciba()` task, stores `PendingStepUp`, returns `StepUpPending`.
- `poll_ciba()`: Tokio task, polls token endpoint at CIBA interval, applies `+5s` on `slow_down`, validates ACR for fido2 (hard-fail), returns `StepUpOutcome`.
- `handle_step_up_result()`: checks `JoinHandle.is_finished()`, returns `StepUpComplete` or `StepUpTimedOut` when done, `StepUpPending` when still running.
- `extract_acr_from_id_token()`: decodes JWT middle segment (base64url), parses ACR claim without signature verification (acceptable — ACR is used for informational reporting after CIBA succeeds; actual security enforcement is `validate_acr()` against `ACR_PHR`).

**`unix-oidc-agent/src/main.rs`** updated in `load_agent_state()`:
- Extracts `issuer`, `client_id`, `client_secret` from `KEY_TOKEN_METADATA` JSON blob.
- Wraps `client_secret` in `SecretString` at extraction (MEM-03 audit boundary).
- Populates new `AgentState` fields.

### Task 2: PAM sudo.rs CIBA Routing

**`pam-unix-oidc/src/sudo.rs`**:

- `SudoError::StepUp(String)` variant added for IPC-level failures.
- `perform_step_up()` now routes Push → `perform_step_up_via_ipc()` and Fido2 → `perform_step_up_via_ipc()` before falling through to device flow.
- `perform_step_up_via_ipc()`: sends `StepUp` IPC JSON, receives `correlation_id`, enters bounded poll loop (PAM-side, 2s timeout per IPC call), routes `Complete`/`TimedOut`/`Pending` responses to the correct `SudoError` variants or `Ok(StepUpResult)`.
- `agent_socket_path()` resolves socket path from `UNIX_OIDC_AGENT_SOCKET` or `XDG_RUNTIME_DIR` fallback.
- `connect_agent_socket()`, `send_ipc_message()`, `read_ipc_response()` — socket helpers with 2s timeout.
- `perform_device_flow_step_up()` extracted from old `perform_step_up()` body, preserving existing device flow logic.
- `log_step_up_initiated()` updated to report actual method (Push > Fido2 > DeviceFlow priority).

**`pam-unix-oidc/src/policy/config.rs`**:
- `challenge_timeout` default raised from 60 to 120 (STP-07).

## Tests Added

### Task 1 — Agent (10 new tests in daemon/socket.rs)
- `test_agent_state_has_oidc_config_fields` — struct fields exist and initialize to None
- `test_step_up_outcome_complete` / `test_step_up_outcome_timed_out` — enum variants
- `test_handle_step_up_no_oidc_config` — returns error when oidc_issuer is None
- `test_concurrent_step_up_same_user_rejected` — concurrent guard (adversarial)
- `test_poll_ciba_complete` — mock HTTP, full flow, returns Complete
- `test_poll_ciba_denied` — mock HTTP, access_denied, returns TimedOut(denied)
- `test_poll_ciba_slow_down_increases_interval` — slow_down adds 5s
- `test_poll_ciba_timeout` — timeout exceeded, returns TimedOut(timeout)
- `test_extract_acr_from_id_token_valid_claim` — JWT middle segment decode

### Task 2 — PAM sudo (6 new tests in sudo.rs)
- `test_sudo_error_step_up_variant` — SudoError::StepUp carries message
- `test_challenge_timeout_defaults_to_120` — STP-07 invariant
- `test_log_step_up_initiated_includes_method` — no-panic audit log test
- `test_perform_step_up_via_ipc_connection_refused` — returns SudoError::StepUp
- `test_step_up_ipc_pending_then_complete` — mock Unix socket, full poll cycle
- `test_step_up_ipc_timed_out_reason_timeout` — mock Unix socket, timeout reason
- `test_step_up_ipc_denied` — mock Unix socket, denied reason

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] pam-unix-oidc was cdylib-only, blocking cross-crate import**
- **Found during:** Task 1
- **Issue:** `use pam_unix_oidc::ciba::...` in unix-oidc-agent failed — cdylib crates produce `.so` only, not importable `.rlib`.
- **Fix:** Added `"rlib"` to `crate-type = ["cdylib", "rlib"]` in pam-unix-oidc/Cargo.toml.
- **Files modified:** pam-unix-oidc/Cargo.toml
- **Commit:** 6dc3b40

**2. [Rule 1 - Bug] pam-unix-oidc dependency not picked up by Cargo**
- **Found during:** Task 1
- **Issue:** Dependency entry placed after `[target.*.dependencies.tss-esapi]` table so Cargo did not parse it as a regular dependency.
- **Fix:** Changed to `[dependencies.pam-unix-oidc]` table syntax in unix-oidc-agent/Cargo.toml.
- **Files modified:** unix-oidc-agent/Cargo.toml
- **Commit:** 6dc3b40

**3. [Rule 2 - Missing export] parse_ciba_error and build_binding_message not re-exported**
- **Found during:** Task 1
- **Issue:** Functions existed in types.rs and client.rs but were absent from ciba/mod.rs public API.
- **Fix:** Added to `pub use` statements in pam-unix-oidc/src/ciba/mod.rs.
- **Files modified:** pam-unix-oidc/src/ciba/mod.rs
- **Commit:** 6dc3b40

**4. [Rule 1 - Bug] AgentState struct literal breakage in 6 existing tests**
- **Found during:** Task 1
- **Issue:** Adding new fields to AgentState without `Default` broke all test struct literals.
- **Fix:** Added `oidc_issuer: None, oidc_client_id: None, oidc_client_secret: None, pending_step_ups: HashMap::new()` to each test literal.
- **Files modified:** unix-oidc-agent/src/daemon/socket.rs
- **Commit:** 6dc3b40

**5. [Rule 3 - Blocking] StepUpResult private_interfaces lint warning**
- **Found during:** Task 2 compilation
- **Issue:** `perform_step_up_via_ipc` was `pub` but `StepUpResult` was `struct` (private) — Rust `private_interfaces` warning.
- **Fix:** Changed both to `pub(crate)` and added `#[derive(Debug)]` for test assertions. Added `#[allow(dead_code)]` on `jti` field.
- **Files modified:** pam-unix-oidc/src/sudo.rs
- **Commit:** 949df9a

### Out-of-Scope Issues Deferred

- `pam-unix-oidc/src/security/jti_cache.rs` doctest fails with type mismatch (`&str` vs `Option<&str>`) — pre-existing, no changes from this plan, logged for future fix.

## Self-Check: PASSED

Files verified to exist:
- unix-oidc-agent/src/daemon/socket.rs: FOUND
- unix-oidc-agent/src/main.rs: FOUND
- pam-unix-oidc/src/sudo.rs: FOUND
- pam-unix-oidc/src/policy/config.rs: FOUND

Commits verified to exist:
- 6dc3b40 (Task 1): FOUND
- 949df9a (Task 2): FOUND

Test results:
- `cargo test -p pam-unix-oidc --lib -- sudo`: 19 passed, 0 failed
- `cargo test --workspace --lib`: 429 passed (301 agent + 128 pam), 0 failed
- `cargo clippy --workspace -- -D warnings`: clean
