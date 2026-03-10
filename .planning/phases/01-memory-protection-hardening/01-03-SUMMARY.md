---
phase: 01-memory-protection-hardening
plan: "03"
subsystem: unix-oidc-agent/storage
tags: [secure-delete, dod-5220, cow-filesystem, ssd-advisory, memory-protection, documentation]
dependency_graph:
  requires:
    - phase: 01-01
      provides: ProtectedSigningKey, ZeroizeOnDrop, mlock
    - phase: 01-02
      provides: SecretString token wrapping, disable_core_dumps, secure_delete.rs (pre-built)
  provides:
    - secure_delete::secure_remove (three-pass DoD 5220.22-M overwrite + unlink)
    - detect_cow_filesystem (btrfs/APFS detection)
    - detect_rotational_device (SSD/flash detection via /sys/block)
    - log_storage_advisories (startup CoW/SSD WARN logging)
    - FileStorage::delete wired to secure_remove
    - CLAUDE.md Memory Protection Invariants section
    - README.md Security Design section
  affects: [unix-oidc-agent/src/storage, documentation]
tech_stack:
  added: []
  patterns:
    - "Best-effort overwrite: DoD 5220.22-M three-pass, log failure, still unlink"
    - "CoW advisory at construction + per-delete for operator visibility"
    - "Chunked buffer overwrite for arbitrary file sizes (OVERWRITE_BUF = 4096)"
key_files:
  created:
    - unix-oidc-agent/src/storage/secure_delete.rs
  modified:
    - unix-oidc-agent/src/storage/file_store.rs
    - unix-oidc-agent/src/storage/mod.rs
    - CLAUDE.md
    - README.md
key-decisions:
  - "Three-pass DoD 5220.22-M (random, complement, random) chosen per user decision; overwrite failure is best-effort (log + still unlink)"
  - "No new dependencies: OsRng from p256::elliptic_curve::rand_core re-export (already transitive dep)"
  - "Per-delete CoW advisory is per-file path (not per storage_dir) for accurate warnings when deletions cross mountpoints"
  - "secure_delete.rs was pre-built in plan 01-02 commit 9517c0a; this plan confirmed and wired it into FileStorage"
requirements-completed: [MEM-05, MEM-06]
duration: 11m
completed: "2026-03-10"
---

# Phase 1 Plan 3: Secure Delete and Memory Protection Documentation Summary

Three-pass DoD 5220.22-M file overwrite in FileStorage::delete with btrfs/APFS/SSD advisories and full Memory Protection Invariants documentation in CLAUDE.md and README.md.

## Performance

- **Duration:** 11m
- **Started:** 2026-03-10T13:25:44Z
- **Completed:** 2026-03-10T13:36:44Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Three-pass secure delete (`secure_remove`): random bytes + complement + random bytes, each pass followed by `fsync`, then `unlink`
- CoW filesystem detection via `statfs(2)` for btrfs (Linux `BTRFS_SUPER_MAGIC`) and APFS (macOS `f_fstypename`)
- Rotational device detection via `/sys/block/{dev}/queue/rotational` on Linux
- `log_storage_advisories()` called at `FileStorage::new()` (startup) and `detect_cow_filesystem()` called per-delete
- `FileStorage::delete()` now delegates to `secure_remove()` — zero-overwrite code removed
- CLAUDE.md: "Memory Protection Invariants" section with 9 numbered invariants, rationale, and limitations
- README.md: "Security Design" section with memory/disk protection tables and NIST SP 800-88 Rev 1 reference

## Task Commits

1. **Task 1: Secure delete module and FileStorage wiring** - `9517c0a` (feat(01-02) — pre-built by previous session; confirmed and verified passing)
2. **Task 2: CLAUDE.md and README.md documentation** - `1b5eba4` (docs)

**Plan metadata:** see below in final commit

## Files Created/Modified

- `unix-oidc-agent/src/storage/secure_delete.rs` — Three-pass overwrite, CoW/SSD detection, advisory logging
- `unix-oidc-agent/src/storage/file_store.rs` — delete() uses secure_remove; new() calls log_storage_advisories
- `unix-oidc-agent/src/storage/mod.rs` — pub mod secure_delete added
- `CLAUDE.md` — Memory Protection Invariants section (9 invariants + limitations)
- `README.md` — Security Design section with memory/disk protection summary

## Decisions Made

- **DoD 5220.22-M three-pass**: random, complement (XOR 0xFF), random — per user decision documented in STATE.md.
- **Best-effort overwrite**: overwrite failure logs at WARN but still unlinks. Key material gone from filesystem even if overwrite fails.
- **No new crate deps**: `OsRng` sourced from `p256::elliptic_curve::rand_core` re-export already in the transitive dep tree. No `rand` crate needed.
- **Per-delete CoW check on file path** (not storage_dir): more accurate if files could theoretically be on different mountpoints.
- `secure_delete.rs` was pre-built during the plan 01-02 execution session alongside the SecretString changes. This plan confirmed it was correct and complete, ran all tests, and added the documentation.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed secrecy 0.10 API incompatibility in socket.rs and main.rs**

- **Found during:** Task 1 (attempting to compile before running tests)
- **Issue:** `socket.rs` used `use secrecy::{ExposeSecret, Secret}` and `Secret<String>` types. In `secrecy 0.10`, the `Secret` type was removed and replaced with `SecretBox<S>` / `SecretString`. This caused `E0432: unresolved import` preventing compilation.
- **Root cause:** The plan 01-02 code was written targeting `secrecy 0.8` API but the Cargo.toml had `secrecy = "0.10"`.
- **Fix:** Changed `Secret<String>` → `SecretString` throughout socket.rs; fixed `Secret::new(s.to_string())` → `SecretString::from(s)`; updated expose_secret().clone() → .to_string() (SecretString returns &str not &String); fixed main.rs to wrap access_token with `SecretString::from` and add `mlock_status: None` to AgentState construction.
- **Files modified:** `unix-oidc-agent/src/daemon/socket.rs`, `unix-oidc-agent/src/main.rs`
- **Verification:** `cargo build -p unix-oidc-agent` succeeds; 63 tests pass
- **Committed in:** `9517c0a` (part of the pre-existing plan 01-02 commit)

**Note on Task 1 pre-completion:** `secure_delete.rs` and the `FileStorage` wiring were pre-built during the plan 01-02 execution session as part of fixing the secrecy API issue. The current session confirmed these changes are correct, verified all 63 tests pass, and proceeded directly to Task 2 (documentation).

---

**Total deviations:** 1 auto-fixed (blocking API incompatibility)
**Impact on plan:** Fix was necessary for compilation and had no effect on plan scope. All plan criteria met.

## Issues Encountered

- A file system linter repeatedly reverted in-progress writes to `file_store.rs` back to the HEAD state during the session. This required using Write tool to overwrite atomically and verified that the HEAD state was actually the correct final state (pre-built in 01-02).

## Next Phase Readiness

- Phase 1 (Memory Protection Hardening) is now complete: MEM-01 through MEM-06 all implemented and tested
- Phase 2 (Keyring Hardening) can proceed — blockers documented in STATE.md regarding `keyring 3.6.3` user-keyring vs session-keyring behavior
- All 63 unit tests passing, clippy clean

## Self-Check: PASSED

Files verified:
- unix-oidc-agent/src/storage/secure_delete.rs: FOUND
- unix-oidc-agent/src/storage/file_store.rs: FOUND
- CLAUDE.md (Memory Protection Invariants): FOUND
- README.md (zeroize reference): FOUND
- .planning/phases/01-memory-protection-hardening/01-03-SUMMARY.md: FOUND

Commits verified:
- 9517c0a (Task 1 — secure_delete pre-built in 01-02 session): FOUND
- 1b5eba4 (Task 2 — documentation): FOUND

Content criteria:
- Memory Protection Invariants in CLAUDE.md: FOUND
- mlock in CLAUDE.md: FOUND
- zeroize in README.md: FOUND
- Three-pass overwrite in secure_delete.rs: FOUND
- detect_cow_filesystem in secure_delete.rs: FOUND
- secure_delete reference in file_store.rs: FOUND

---
*Phase: 01-memory-protection-hardening*
*Completed: 2026-03-10*
