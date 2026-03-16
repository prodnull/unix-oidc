---
phase: 25-phase-25-security-hardening
verified: 2026-03-15T20:00:00Z
status: human_needed
score: 6/6 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 5/6
  gaps_closed:
    - "SHRD-06: probe_dbus_session_encryption() now uses dbus-send to call OpenSession with 'plain' algorithm on Linux — returns Plain/Encrypted/Unknown with real OS-level signal instead of unconditional Unknown"
    - "SHRD-06: Unknown + strict mode now emits tracing::warn! rather than silently allowing"
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Verify ANSI escape stripping in a real terminal session"
    expected: "Login prompt shows clean URL without any terminal-control side effects when verification_uri contains embedded escape sequences"
    why_human: "Terminal rendering behavior cannot be verified programmatically"
---

# Phase 25: Security Hardening Verification Report

**Phase Goal:** Algorithm confusion attacks are blocked by an explicit allowlist; HTTPS is enforced for all OIDC endpoints at config load time; terminal escape sequences from IdP-supplied URIs cannot reach user terminals; D-Bus Secret Service sessions require encryption
**Verified:** 2026-03-15T20:00:00Z
**Status:** human_needed
**Re-verification:** Yes — after gap closure (SHRD-06 D-Bus probe implementation)

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Algorithm comparison uses explicit enum match (not serde/Debug), and symmetric HS* algorithms are blocked | VERIFIED | `key_algorithm_to_algorithm()` in `validation.rs`: 9-arm exhaustive match returning `Err(UnsupportedKeyAlgorithm)` for HS256/384/512; regression tests pass (372 pam-unix-oidc tests) |
| 2 | When JWKS key omits `alg` and token claims HS256, validation rejects with UnsupportedAlgorithm (allowlist blocks it) | VERIFIED | `DEFAULT_ALLOWED_ALGORITHMS` excludes all HS* variants; allowlist check wired in `verify_and_decode()`; `test_default_allowlist_no_symmetric` confirmed |
| 3 | Per-issuer `allowed_algorithms` config field overrides the default allowlist | VERIFIED | `IssuerConfig.allowed_algorithms: Option<Vec<String>>` in `config.rs`; propagated through `ValidationConfig`; `test_issuer_config_allowed_algorithms_yaml` passes |
| 4 | BREAK_GLASS_AUTH events appear at syslog CRITICAL severity when `alert_on_use=true` | VERIFIED | `syslog_severity()` in `audit.rs` returns `Critical` for `alert_on_use=true`; `test_break_glass_auth_alert_on_use_true_is_critical` and `test_syslog_severity_mapping` pass |
| 5 | A config file specifying http:// for an issuer URL is rejected at load time with clear error | VERIFIED | `validate_https_url()` called in `load_from()` at config.rs; `test_load_from_rejects_http_issuer_url` passes |
| 6 | Terminal escape sequences from IdP-supplied URIs are stripped before display | VERIFIED | `sanitize_terminal_output()` called in `main.rs` before `verification_uri` and `verification_uri_complete` display; 15 sanitize tests pass covering CSI/OSC/DCS/APC/PM/SOS/C0/C1 |
| 7 | D-Bus plain session detection emits structured audit event and logs when detected | VERIFIED | `evaluate_dbus_encryption()` emits `DBUS_PLAIN_SESSION` target audit event; 7 enforcement unit tests pass; probe now returns real signal on Linux |
| 8 | D-Bus Secret Service session with strict policy rejects plain session | VERIFIED | `evaluate_dbus_encryption(Strict, Plain)` → `Reject`; `probe_dbus_session_encryption()` on Linux calls `dbus-send OpenSession string:plain` — plain accepted returns `Plain`, plain rejected returns `Encrypted`, probe failure returns `Unknown`; `Unknown + Strict` emits `tracing::warn!` (no silent allow); call sites at router.rs lines 644 and 750 |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/oidc/validation.rs` | `key_algorithm_to_algorithm()`, `DEFAULT_ALLOWED_ALGORITHMS`, allowlist enforcement | VERIFIED | 9-arm exhaustive match; 9-algorithm allowlist; wired in `verify_and_decode()` |
| `pam-unix-oidc/src/policy/config.rs` | `validate_https_url()`, `allowed_algorithms` on `IssuerConfig`, HTTPS in `load_from()` | VERIFIED | All present and substantive |
| `pam-unix-oidc/src/device_flow/types.rs` | `validate_uris()` reuses shared `validate_https_url` | VERIFIED | Imports and calls `crate::policy::config::validate_https_url` |
| `unix-oidc-agent/src/sanitize.rs` | `sanitize_terminal_output()` strips all terminal escape sequences | VERIFIED | Full implementation; 15 tests covering all sequence types |
| `unix-oidc-agent/src/main.rs` | `sanitize_terminal_output()` called before display of `verification_uri` | VERIFIED | Called before both `verification_uri` and `verification_uri_complete` display; warns when `was_modified` |
| `unix-oidc-agent/src/storage/router.rs` | D-Bus encryption policy types, `evaluate_dbus_encryption()`, real probe integration | VERIFIED | `probe_dbus_session_encryption()` on Linux uses `dbus-send` two-step probe (name owner check then OpenSession plain); TODO(SHRD-06) comment removed; 7 enforcement tests pass; wired at both forced and auto-detect call sites |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `validation.rs` | `IssuerConfig.allowed_algorithms` | `allowed_algorithms` read from `ValidationConfig` | WIRED | Propagated in `auth.rs` and `sudo.rs` |
| `config.rs load_from()` | HTTPS scheme check | `validate_https_url()` called for each issuer | WIRED | `validate_https_url(&issuer.issuer_url, "issuer_url")` at config load |
| `main.rs` | `sanitize.rs` | `sanitize_terminal_output()` called before `verification_uri` display | WIRED | Import present; called before both URI display points |
| `router.rs detect_auto()` | D-Bus probe → enforcement decision | `probe_dbus_session_encryption()` → `evaluate_dbus_encryption(dbus_policy, dbus_session)` | WIRED | Both auto-detect (line 750) and forced (line 644) paths call probe then evaluate; `Reject` causes fallthrough or `Err` return respectively |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SHRD-01 | 25-01 | Algorithm comparison uses explicit enum match | SATISFIED | `key_algorithm_to_algorithm()` with exhaustive arms; regression tests pass |
| SHRD-02 | 25-01 | Algorithm allowlist when JWKS key omits `alg` | SATISFIED | `DEFAULT_ALLOWED_ALGORITHMS` enforced; HS256 blocked |
| SHRD-03 | 25-01 | BREAK_GLASS_AUTH logged at CRITICAL syslog severity | SATISFIED | `syslog_severity()` returns `Critical` for `alert_on_use=true`; 4 regression tests pass |
| SHRD-04 | 25-01 | HTTPS validated for issuer URL at config load time and device flow `verification_uri` | SATISFIED | `validate_https_url()` in `load_from()` and `validate_uris()`; HTTPS tests pass |
| SHRD-05 | 25-02 | Terminal escape sequences sanitized in IdP-supplied `verification_uri` before display | SATISFIED | `sanitize_terminal_output()` in `main.rs`; 15 sanitize tests pass |
| SHRD-06 | 25-02 | D-Bus Secret Service rejects plain (unencrypted) sessions; strict/warn/disabled config toggle | SATISFIED | `probe_dbus_session_encryption()` on Linux uses `dbus-send` to probe server capability; `evaluate_dbus_encryption()` enforces strict/warn/disabled; `Unknown + Strict` warns explicitly; both call sites wired; 7 tests pass |

No orphaned requirements — all 6 SHRD IDs declared in plan frontmatter are accounted for and marked Complete in REQUIREMENTS.md.

### Anti-Patterns Found

None. The `TODO(SHRD-06)` stub comment at the previous line 186 has been removed. No placeholder implementations, empty returns, or deferred logic detected in the modified files.

### Human Verification Required

#### 1. Terminal Injection Resistance

**Test:** Construct a test OIDC device flow response containing a `verification_uri` with embedded ANSI escape sequences (e.g., `https://login.example.com\x1b[2J\x1b[H`) and run `unix-oidc-agent login`. Observe the terminal.
**Expected:** The login prompt displays only `https://login.example.com` without any screen-clear, cursor movement, or other side effects. The agent logs a WARN about sanitized bytes.
**Why human:** Terminal rendering behavior is an environmental effect that grep cannot verify.

### Re-verification Summary

**Gap closed: SHRD-06 probe implementation**

The previous gap was that `probe_dbus_session_encryption()` returned `DbusSessionEncryption::Unknown` unconditionally, making the enforcement infrastructure unreachable in production. The fix implements a two-step Linux probe using `dbus-send`:

1. Name owner check — verifies `org.freedesktop.secrets` is registered on the session bus. Returns `Unknown` if not (correct: Secret Service is not running, no session to probe).
2. `OpenSession string:plain` call — probes whether the Secret Service daemon accepts unencrypted sessions. Returns `Plain` on success (server allows unencrypted, strict mode will reject this backend), `Encrypted` on rejection (server requires DH, all modes allow).

The second part of the previous gap — "Unknown should warn in strict mode rather than silently allowing" — is also fixed: the `DbusSessionEncryption::Unknown + DbusEncryptionPolicy::Strict` branch now calls `tracing::warn!()` with actionable guidance before returning `Allow`.

The `Unknown → Allow` behavior is preserved (not changed to `Reject`) which is architecturally correct: inability to determine encryption status is different from confirmed plain-text. Blocking on `Unknown` would break all non-D-Bus environments and containers where `dbus-send` is not available.

All 6 requirements satisfied. No regressions in SHRD-01 through SHRD-05. Workspace builds clean. 372 pam-unix-oidc tests pass, 186+ unix-oidc-agent unit tests pass.

---

_Verified: 2026-03-15T20:00:00Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification: Yes — after SHRD-06 gap closure_
