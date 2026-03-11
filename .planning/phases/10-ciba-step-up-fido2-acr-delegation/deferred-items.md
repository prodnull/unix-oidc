# Deferred Items — Phase 10

## Pre-existing Issues (Out of Scope for Phase 10)

### jti_cache.rs doctest type mismatch

**File:** `pam-unix-oidc/src/security/jti_cache.rs` (lines 55-65)

**Issue:** Doctest passes `"jti-123"` (`&str`) to `check_and_record()` which expects `Option<&str>`. This is a pre-existing failure from before Phase 10 — last touched in commit `0b03de9` (Phase 06).

**Symptom:** `cargo test --workspace` doctest fails with `E0308: mismatched types`.

**Fix:** Wrap doctest values in `Some(...)`: change `check_and_record("jti-123", ...)` to `check_and_record(Some("jti-123"), ...)`.

**Why deferred:** Out of scope per deviation rules (pre-existing, no changes from this plan). Phase 10 lib tests pass cleanly (429/429). Only doctest affected.
