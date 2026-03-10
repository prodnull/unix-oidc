# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** Phase 1 — Memory Protection Hardening

## Current Position

Phase: 1 of 3 (Memory Protection Hardening)
Plan: 0 of 3 in current phase
Status: Ready to plan
Last activity: 2026-03-10 — Roadmap created, requirements defined, research complete

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: -

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: n/a
- Trend: n/a

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Pre-roadmap]: Keyring as default, file as fallback — headless servers may lack D-Bus; graceful degradation needed
- [Pre-roadmap]: `zeroize` for memory + deletion — RustCrypto standard, derives work with existing types
- [Pre-roadmap]: Hardware keys as optional cargo features — avoids requiring YubiKey/TPM libs for all users
- [Pre-roadmap]: mlock via `libc::mlock` directly — already a workspace dependency, zero new deps
- [Research]: `yubikey` 0.8.0 crate rejected — unaudited, experimental warning, stale 18 months; use `cryptoki` 0.12.0 (PKCS#11) instead
- [Research]: `p256` must stay on 0.13 — 0.14.x removes `jwk` feature required by `public_key_jwk()`

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 2]: `keyring` 3.6.3 `keyutils` backend user-keyring vs. session-keyring behavior unconfirmed — must validate empirically before Phase 2 PR (Pitfall 2 in research). Plan 02-01 is a spike for this.
- [Phase 3]: `cryptoki` 0.12.0 `CKM_ECDSA` raw-digest DPoP signing path unprototyped — Plan 03-01 is a spike. If path is invalid, hardware signer strategy needs revision.
- [Phase 3]: TPM P-256 ECDSA capability varies by device — cloud vTPMs (AWS/GCP/Azure) need testing in addition to physical TPMs.

## Session Continuity

Last session: 2026-03-10
Stopped at: Roadmap and STATE created; ready to begin Phase 1 planning
Resume file: None
