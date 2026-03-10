---
phase: 04-hardware-signer-refresh-fix
verified: 2026-03-10T18:30:00Z
status: passed
score: 3/3 must-haves verified
re_verification: false
---

# Phase 4: Hardware Signer Refresh Fix Verification Report

**Phase Goal:** Token refresh preserves signer_type metadata so hardware signer users retain their DPoP binding across refresh + daemon restart cycles
**Verified:** 2026-03-10T18:30:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | After hardware signer login + token refresh, stored metadata still contains the original signer_type value | VERIFIED | `"signer_type": metadata["signer_type"]` present in `run_refresh()` at main.rs:868 and `perform_token_refresh()` at socket.rs:541; both store to `KEY_TOKEN_METADATA` via `storage.store()` |
| 2 | After hardware signer login + token refresh + daemon restart, `load_agent_state()` reconstructs the hardware signer (not software fallback) | VERIFIED | `load_agent_state()` reads `KEY_TOKEN_METADATA`, extracts `signer_type_from_metadata` at main.rs:941–944, then dispatches to `build_signer(hw_spec, &hw_config)` at main.rs:964 for any value other than None or "software" |
| 3 | A regression test proves signer_type survives a simulated refresh cycle | VERIFIED | `test_refresh_metadata_preserves_signer_type` in main.rs:1122–1176 covers yubikey:9a, tpm, software, and legacy (missing) cases; test passes: `1 passed; 0 failed` |

**Score:** 3/3 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/main.rs` | `run_refresh()` forwarding signer_type in updated_metadata | VERIFIED | Fix at line 868 with explanatory comment; test module at lines 1098–1177 |
| `unix-oidc-agent/src/daemon/socket.rs` | `perform_token_refresh()` forwarding signer_type in updated_metadata | VERIFIED | Fix at line 541 with explanatory comment; function confirmed at line 418 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `run_refresh()` updated_metadata | `load_agent_state()` signer_type_from_metadata | KEY_TOKEN_METADATA storage round-trip | WIRED | main.rs:870 stores metadata; main.rs:935–944 retrieves and parses signer_type; main.rs:947 dispatches to hardware signer branch |
| `perform_token_refresh()` updated_metadata | `load_agent_state()` signer_type_from_metadata | KEY_TOKEN_METADATA storage round-trip | WIRED | socket.rs:543–544 stores metadata; same load_agent_state() consumer reads it on daemon restart |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| HW-01 | 04-01-PLAN.md | YubiKeySigner implementing DPoPSigner via PKCS#11 with P-256 ECDSA | SATISFIED | signer_type "yubikey:9a" now preserved through refresh; load_agent_state() calls build_signer("yubikey:9a") on restart, reconstructing YubiKeySigner — the hardware binding is durable across the refresh cycle |
| HW-02 | 04-01-PLAN.md | TpmSigner implementing DPoPSigner via tss-esapi with P-256 ECDSA | SATISFIED | signer_type "tpm" now preserved through refresh; load_agent_state() calls build_signer("tpm") on restart, reconstructing TpmSigner |
| HW-06 | 04-01-PLAN.md | `unix-oidc-agent login --signer yubikey\|tpm\|software` CLI flag for backend selection | SATISFIED | The signer_type written at login (capturing the --signer flag's selection) is now faithfully forwarded through both refresh paths, making the CLI selection durable beyond the initial login |

**Orphaned requirements check:** REQUIREMENTS.md traceability table maps HW-01, HW-02, and HW-06 to "Phase 3, Phase 4" — all three are accounted for in the plan frontmatter. No orphaned requirements.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | — | — | No anti-patterns found in modified files |

Scan results:
- No TODO/FIXME/HACK/PLACEHOLDER comments in modified files
- No stub implementations (return null, empty JSON)
- No console.log-only handlers
- `cargo clippy -p unix-oidc-agent -- -D warnings`: clean, no warnings

### Human Verification Required

None for this phase. The fix is a JSON field-forwarding change verified by:
1. Direct grep confirming the field is present in both refresh paths
2. Code reading confirming the storage round-trip is complete (store → retrieve → dispatch)
3. Passing regression test covering all four signer variants (yubikey, tpm, software, legacy/missing)

The end-to-end flow (hardware device present, full refresh cycle, daemon restart) requires a physical YubiKey or TPM to exercise, but the code path is fully traced and the fix is unambiguous.

### Commits Verified

| Commit | Description | Exists |
|--------|-------------|--------|
| `c3c7fc3` | test(04-01): add regression test for signer_type preservation across refresh | Yes |
| `fc8f0b2` | fix: preserve signer_type across token refresh in both paths | Yes |

### Summary

The phase goal is fully achieved. Both refresh code paths (`run_refresh()` in main.rs and `perform_token_refresh()` in socket.rs) now forward `signer_type` from original metadata to `updated_metadata`, closing the silent data-loss defect where hardware signer users lost their DPoP binding after any token refresh + daemon restart cycle.

The fix is minimal (one line + comment in each function), correctly placed, stored via the same `KEY_TOKEN_METADATA` key that `load_agent_state()` already reads, and covered by a regression test that exercises all four signer variants including the legacy case where no signer_type field is present.

Requirements HW-01, HW-02, and HW-06 are satisfied: the hardware signer backends (built in Phase 3) now retain their bindings across the full refresh lifecycle.

---

_Verified: 2026-03-10T18:30:00Z_
_Verifier: Claude (gsd-verifier)_
