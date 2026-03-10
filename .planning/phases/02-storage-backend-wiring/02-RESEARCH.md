# Phase 2: Storage Backend Wiring - Research

**Researched:** 2026-03-10
**Domain:** Rust credential storage — `keyring` 3.6.3 crate, Linux keyutils, D-Bus Secret Service, StorageRouter design
**Confidence:** HIGH (primary findings from direct crate source inspection; no guesswork)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Three-tier fallback order: keyring (D-Bus Secret Service / macOS Keychain) → keyutils @u (Linux headless) → file storage
- Probe mechanism: write/read/delete cycle with a dedicated sentinel key (`unix-oidc-probe`) at startup
- Re-probe every startup — no cached backend selection
- If a previously-used backend becomes unavailable: fall through to next backend, log WARN with actionable message
- `UNIX_OIDC_STORAGE_BACKEND=keyring|keyutils|file` env var override; override only takes effect if the forced backend passes the probe; if forced backend fails probe, log ERROR and refuse to start
- Auto-migrate on first startup when keyring probe succeeds AND file-stored credentials exist
- Atomic migration: if any of the 4 keys fails, rollback all successfully-migrated keys from keyring and stay on file storage
- After successful migration, verify each key via read-back from keyring, then secure-delete the files using Phase 1's 3-pass DoD overwrite
- Migration scope: file → keyring only (no keyutils → D-Bus upgrade; deferred to ASTOR-02)
- Status output: `Storage: keyring (Secret Service)` / `Migration: migrated` etc.
- Descriptive naming with provider in parentheses
- `--verbose` adds probe results, fallback reason, keyring service name, file storage path
- Human-readable text only; no --json output
- keyutils keys set with no timeout; agent manages its own token expiry
- No special container detection; probe chain handles containers naturally
- CI integration test: Docker container with D-Bus socket masked; credentials persist across simulated process restart

### Claude's Discretion
- Internal `StorageRouter` struct design and method signatures
- Probe key name and value (suggested: `unix-oidc-probe`)
- keyutils API interaction details (how the `keyring` crate maps to @u vs @s — spike in plan 02-01 determines this)
- Error type extensions to `StorageError` for backend detection failures
- Exact `--verbose` output formatting
- Test fixture design for headless CI test

### Deferred Ideas (OUT OF SCOPE)
- None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| STOR-01 | Runtime keyring backend detection via probe write/read/delete at daemon startup | StorageRouter::detect() pattern; probe must test ACTUAL backend not just constructor success |
| STOR-02 | KeyringStorage activated as default backend when keyring is available, FileStorage as automatic fallback | Feature flag fix is prerequisite; StorageRouter wraps selection logic |
| STOR-03 | File-to-keyring migration for existing file-stored credentials (detect on startup, migrate transparently, log migration event) | Atomic rollback pattern; 4 keys; verify read-back before delete |
| STOR-04 | Linux headless support via `keyutils` user keyring (`@u`, not session `@s`) when D-Bus Secret Service is unavailable | Requires separate `keyutils` crate or feature-gated keyring; spike required |
| STOR-05 | File deletion uses random-overwrite + unlink, with documented limitation that CoW/SSD filesystems may retain copies | Already implemented in Phase 1; just needs to be called during migration |
| STOR-06 | `unix-oidc-agent status` reports active storage backend (keyring vs file) and migration status | Protocol extension: add `storage_backend` and `migration_status` to `AgentResponseData::Status` |
| STOR-07 | Documentation updated with storage architecture, backend selection logic, migration instructions, and headless deployment guide | docs/ update; CLAUDE.md update |
</phase_requirements>

---

## Summary

Phase 2 wires in a three-tier storage backend selection system (`StorageRouter`) that replaces the seven hardcoded `FileStorage::new()` calls in `main.rs` and `socket.rs`. The primary research surface is the `keyring` 3.6.3 crate, which has two critical findings that determine the implementation path.

**Critical Finding 1 — Feature flags are missing.** The project's `Cargo.toml` declares `keyring = "3"` with NO features. The keyring crate documents that it has no default features: without `sync-secret-service` or `linux-native`, it falls back to its in-memory mock store on Linux. The existing `KeyringStorage` is therefore silently writing to a mock in any Linux CI or production build. Feature flags must be added as the first step before any detection logic can work.

**Critical Finding 2 — keyutils session vs. persistent keyring behavior.** Reading `keyring-3.6.3/src/keyutils.rs` directly: the `linux-native` backend uses `KeyRingIdentifier::Session` as the primary anchor (`@s`) but also links to the persistent keyring (`KeyRing::get_persistent(KeyRingIdentifier::Session)`). The persistent keyring IS the user-persistent keyring (analogous to `@u`) and survives logout but NOT reboot. The CONTEXT.md requirement for `@u` semantics is achievable via the persistent link that `linux-native` maintains — credentials stored under `linux-native` survive SSH session logout and reboot because the persistent keyring has a configurable expiry (default ~3 days from `/proc/sys/kernel/keys/persistent_keyring_expiry`), not because they're in the session keyring. The spike in plan 02-01 must verify this empirically.

**Primary recommendation:** Add `sync-secret-service` and `linux-native` features to `keyring` in `Cargo.toml`. Implement `StorageRouter` as a concrete struct implementing `SecureStorage`, selected by a `detect()` factory function. Use `set_default_credential_builder()` from the keyring API to switch backends at runtime rather than using two separate structs.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `keyring` | 3.6.3 (already in Cargo.lock) | D-Bus Secret Service + keyutils backends | Already in project; wraps libsecret on Linux, Keychain on macOS |
| `linux-keyutils` | transitive via `keyring linux-native` | Kernel keyutils syscalls | Pulled in by `linux-native` feature; no direct dep needed |
| `dbus-secret-service` | transitive via `keyring sync-secret-service` | D-Bus Secret Service | Pulled in by `sync-secret-service` feature |

### Required Feature Flag Change (CRITICAL prerequisite)

The project's `unix-oidc-agent/Cargo.toml` must change:

```toml
# BEFORE (mock store on Linux — no actual storage)
keyring = "3"

# AFTER (real backends enabled)
keyring = { version = "3", features = [
    "sync-secret-service",   # D-Bus Secret Service (GNOME Keyring / KWallet) on Linux
    "linux-native",          # kernel keyutils fallback for headless Linux
    "apple-native",          # macOS Keychain
] }
```

With both `sync-secret-service` and `linux-native` specified and no "combo" feature, `secret-service` is the default on Linux (per keyring docs: "If you don't enable a combo keystore on Linux, but you do enable both the native and secret service keystores, the secret service will be the default"). `StorageRouter` will explicitly select the backend via `set_default_credential_builder()` rather than relying on the compile-time default.

**Additional system dependency for CI:** `libdbus-1-dev` (or `libsecret-1-dev`) must be present in the GitHub Actions `ci.yml` `apt-get install` step for `sync-secret-service` to compile.

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `keyring::mock` | built-in | Mock credential store for unit tests | Use `set_default_credential_builder(keyring::mock::default_credential_builder())` in test setup |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `keyring` crate | `secret-service` crate directly | More control over D-Bus but no keyutils support; `keyring` already in tree |
| `keyring` `linux-native` | Direct `linux-keyutils` crate | More control over `@u` vs `@s` selection; adds a direct dependency; assess after spike |

**Installation (after feature flag change):**
```bash
# System deps needed on Linux CI
sudo apt-get install -y libdbus-1-dev pkg-config

# Re-resolve lockfile
cargo update -p keyring
```

---

## Architecture Patterns

### Recommended Project Structure
```
unix-oidc-agent/src/storage/
├── mod.rs               # SecureStorage trait, StorageError, key constants
├── file_store.rs        # FileStorage (existing, now last-resort fallback)
├── keyring_store.rs     # KeyringStorage (existing, needs feature fix)
├── keyutils_store.rs    # KeyutilsStorage (NEW — Linux headless via linux-native)
├── router.rs            # StorageRouter (NEW — detect() + fallback chain)
└── secure_delete.rs     # secure_remove() (existing, Phase 1)
```

### Pattern 1: StorageRouter with Probe-Based Detection

**What:** A factory function `StorageRouter::detect()` probes each backend in order and returns the first that passes a write/read/delete cycle.

**When to use:** Called once per process startup, before any credential operations.

**Design:**
```rust
// Source: design derived from keyring 3.6.3 API (crate source inspected directly)

/// Which backend is active and its human-readable name for status reporting
#[derive(Debug, Clone)]
pub enum BackendKind {
    SecretService,        // "keyring (Secret Service)"
    KeyutilsUser,         // "keyring (keyutils @u)"
    MacOsKeychain,        // "keyring (macOS Keychain)"
    File,                 // "file (fallback)"
}

impl BackendKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            BackendKind::SecretService => "keyring (Secret Service)",
            BackendKind::KeyutilsUser  => "keyring (keyutils @u)",
            BackendKind::MacOsKeychain => "keyring (macOS Keychain)",
            BackendKind::File          => "file (fallback)",
        }
    }
}

pub struct StorageRouter {
    backend: Box<dyn SecureStorage>,
    pub kind: BackendKind,
}

impl StorageRouter {
    /// Probe-based backend detection.
    ///
    /// Probes in order: Secret Service → keyutils @u → file.
    /// Returns the first backend that passes the write/read/delete probe.
    pub fn detect() -> Result<Self, StorageError> {
        // Check env var override first
        if let Ok(forced) = std::env::var("UNIX_OIDC_STORAGE_BACKEND") {
            return Self::detect_forced(&forced);
        }

        #[cfg(target_os = "linux")]
        if let Ok(router) = Self::probe_secret_service() {
            info!("Storage backend: Secret Service (D-Bus)");
            return Ok(router);
        }

        #[cfg(target_os = "linux")]
        if let Ok(router) = Self::probe_keyutils() {
            info!("Storage backend: keyutils user keyring");
            return Ok(router);
        }

        #[cfg(target_os = "macos")]
        if let Ok(router) = Self::probe_macos_keychain() {
            info!("Storage backend: macOS Keychain");
            return Ok(router);
        }

        info!("Storage backend: file (fallback) — all keyring probes failed");
        let file = FileStorage::new()?;
        Ok(Self { backend: Box::new(file), kind: BackendKind::File })
    }
}
```

### Pattern 2: Atomic Migration with Rollback

**What:** Read all 4 keys from FileStorage, write them to keyring, verify via read-back, then secure-delete from file. On any failure, delete all successfully-written keyring entries before returning.

**Critical detail:** The 4 keys to migrate are the constants in `mod.rs`:
- `KEY_DPOP_PRIVATE` = `"unix-oidc-dpop-key"`
- `KEY_ACCESS_TOKEN` = `"unix-oidc-access-token"`
- `KEY_REFRESH_TOKEN` = `"unix-oidc-refresh-token"`
- `KEY_TOKEN_METADATA` = `"unix-oidc-token-metadata"`

**When to use:** Called after `StorageRouter::detect()` returns a non-file backend, if `FileStorage` contains any of the 4 keys.

```rust
// Source: design derived from existing storage trait and key constants
pub fn maybe_migrate(router: &StorageRouter, file: &FileStorage)
    -> Result<usize, StorageError>
{
    let keys = [KEY_DPOP_PRIVATE, KEY_ACCESS_TOKEN,
                KEY_REFRESH_TOKEN, KEY_TOKEN_METADATA];

    // Collect all file-stored values that exist
    let to_migrate: Vec<(&str, Vec<u8>)> = keys.iter()
        .filter_map(|k| file.retrieve(k).ok().map(|v| (*k, v)))
        .collect();

    if to_migrate.is_empty() {
        return Ok(0);  // Nothing to migrate
    }

    let mut migrated: Vec<&str> = Vec::new();

    for (key, value) in &to_migrate {
        match router.store(key, value) {
            Ok(()) => {
                // Verify read-back before marking as migrated
                match router.retrieve(key) {
                    Ok(read_back) if read_back == *value => {
                        migrated.push(key);
                    }
                    _ => {
                        // Read-back failed: rollback all migrated entries
                        rollback_migration(router, &migrated)?;
                        return Err(StorageError::Migration(
                            format!("read-back verification failed for key '{}'", key)
                        ));
                    }
                }
            }
            Err(e) => {
                rollback_migration(router, &migrated)?;
                return Err(e);
            }
        }
    }

    // All migrated and verified: secure-delete from file
    let count = migrated.len();
    for key in &migrated {
        // Best-effort deletion; failure logged but does not abort
        if let Err(e) = file.delete(key) {
            warn!(key, error = %e, "Failed to delete migrated file; manual cleanup needed");
        }
    }

    info!("migrated {} credentials from file storage to keyring", count);
    Ok(count)
}
```

### Pattern 3: Protocol Extension for Status Reporting

**What:** Extend `AgentResponseData::Status` with `storage_backend` and `migration_status` fields, and add them to `AgentState`.

**When to use:** During status command handling in `socket.rs` and `main.rs`.

```rust
// Source: existing protocol.rs pattern; extend AgentResponseData::Status
Status {
    logged_in: bool,
    username: Option<String>,
    thumbprint: Option<String>,
    token_expires: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mlock_status: Option<String>,
    // NEW:
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_backend: Option<String>,    // "keyring (Secret Service)" etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    migration_status: Option<String>,  // "migrated", "not migrated", "n/a"
}
```

**Status command output (non-daemon path):** The `run_status()` function in `main.rs` also has a path where the agent isn't running and it directly calls `FileStorage::new()` (line 242). This path must call `StorageRouter::detect()` instead to show correct backend info.

### Anti-Patterns to Avoid

- **Constructing `KeyringStorage` without feature flags active:** Without `sync-secret-service` or `linux-native`, `Entry::new()` uses the mock store. The probe will succeed (mock always succeeds) but nothing will be persisted. Always verify the `Cargo.toml` features are set before testing the probe.
- **Using `@s` (session keyring) alone for headless persistence:** The `linux-native` feature's session anchor is `@s`, but it ALSO links to the persistent keyring. Relying only on `@s` means credentials are lost on SSH session logout. The persistent link is what enables headless survival — confirm the `persistent` field is `Some(...)` in the constructed `KeyutilsCredential` during the spike.
- **Caching backend selection:** CONTEXT.md mandates re-probe every startup. Don't add a config file or env var that stores the last-used backend.
- **Partial migration state in keyring:** If rollback fails (e.g., keyring entry won't delete), log WARN with the orphaned key names. Never leave the code in a state where it thinks migration succeeded when the rollback itself failed.
- **env var override silently falling through:** The CONTEXT.md decision is explicit: if `UNIX_OIDC_STORAGE_BACKEND` is set and the forced backend fails its probe, log ERROR and return `Err` (don't fall through to the next backend).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| D-Bus Secret Service wire protocol | Custom D-Bus code | `keyring` + `sync-secret-service` feature | Extremely complex; session bus discovery, collection unlock, encryption negotiation |
| Kernel keyutils syscalls | `unsafe` keyctl(2) directly | `keyring` + `linux-native` feature → `linux-keyutils` crate | Correct error mapping for all edge cases (key revoked, expired, session loss) is non-trivial |
| Mock store for unit tests | In-memory HashMap behind trait | `keyring::mock::default_credential_builder()` + `set_default_credential_builder()` | Built into keyring crate; tests work cross-platform |
| Backend capability detection | Custom binary parsing / sysfs inspection | Write/read/delete probe against the actual backend | D-Bus availability is not a simple socket test; service may be running but locked or misconfigured |

**Key insight:** The keyring crate's `set_default_credential_builder()` API allows switching the backend at runtime without needing separate struct types per backend. This is the correct design for `StorageRouter::detect_forced()`.

---

## Common Pitfalls

### Pitfall 1: Missing Feature Flags (CONFIRMED BUG IN CURRENT CODE)

**What goes wrong:** `keyring = "3"` with no features activates the mock credential store on Linux. Probe succeeds (mock never fails), agent appears to store credentials, but nothing persists. After restart, all credentials are gone.

**Why it happens:** The `keyring` crate documents "There are no default features in this crate: you must specify explicitly which platform-specific credential stores you intend to use." This is an unusual crate design. CI passes because the mock is used in tests.

**How to avoid:** Add features to `unix-oidc-agent/Cargo.toml`:
```toml
keyring = { version = "3", features = ["sync-secret-service", "linux-native", "apple-native"] }
```

**Warning signs:** Probe succeeds but `keyring-cli` tool shows no entry stored; credentials vanish on restart.

### Pitfall 2: keyutils Persistence — Session vs. Persistent Keyring

**What goes wrong:** Credentials stored in the session keyring (`@s`) are lost when the SSH session ends. The requirement is that credentials survive SSH session logout.

**Why it happens:** The `linux-native` backend in `keyring-3.6.3/src/keyutils.rs` uses `Session` as the primary anchor but calls `KeyRing::get_persistent(KeyRingIdentifier::Session)` to obtain and link the persistent keyring. The persistent link provides post-logout survival. If `get_persistent()` returns an error (e.g., the kernel is older or the persistent keyring quota is exceeded), the credential only lives in `@s`.

**How to avoid:** The Plan 02-01 spike must verify: after storing with `linux-native`, log out of the SSH session (simulated by killing the session keyring), then verify the key is still retrievable. Check `KeyutilsCredential.persistent` is `Some(_)` not `None`.

**Warning signs:** `keyctl show @u` does not show the stored key; key retrieval fails after `keyctl new_session`.

### Pitfall 3: `sync-secret-service` Requires `libdbus-1-dev` at Compile Time

**What goes wrong:** CI build fails with `pkg-config: error: Package 'dbus-1', required by 'virtual:world', not found`.

**Why it happens:** `dbus-secret-service` links against the system D-Bus library at compile time.

**How to avoid:** Add to `ci.yml` install step: `sudo apt-get install -y libdbus-1-dev`.

**Warning signs:** Compile error about `dbus-1` or `pkg-config`.

### Pitfall 4: Empty Password/Secret Rejection by keyutils

**What goes wrong:** `keyutils.rs` returns `ErrorCode::Invalid("secret", "cannot be empty")` if `set_secret` is called with an empty slice.

**Why it happens:** The Linux kernel keyutils subsystem does not permit zero-length key payloads.

**How to avoid:** The probe key value must be non-empty. The existing `KeyringStorage` base64-encodes values; even a 1-byte input produces a non-empty encoded string. But be careful: the DPoP private key bytes or token bytes should never be empty, so this is primarily a concern for probe/test scenarios.

### Pitfall 5: `load_or_create_signer` Signature Takes `&FileStorage`

**What goes wrong:** After replacing `FileStorage::new()` with `StorageRouter::detect()`, the call `load_or_create_signer(&storage)` fails because the function signature is `fn load_or_create_signer(storage: &FileStorage)` (main.rs:810).

**Why it happens:** The function was written against the concrete type.

**How to avoid:** Change the signature to `fn load_or_create_signer(storage: &dyn SecureStorage)`. This is the cleanest fix. Alternatively, downcast via `as_any()` but that is worse design.

### Pitfall 6: Rollback Ordering

**What goes wrong:** If migration of key 3 fails and rollback attempts to delete key 1 and key 2 from keyring, the rollback `delete()` call may itself fail (e.g., keyring became unavailable). The agent ends up with partial state in both backends.

**How to avoid:** Log each rollback failure at WARN with the specific key name. Treat rollback failure as best-effort (like secure_delete). Document that in this edge case the user may have orphaned keyring entries and can use `unix-oidc-agent reset --force` to clear all.

---

## Code Examples

### Enabling the Correct Backend with `set_default_credential_builder`

```rust
// Source: keyring-3.6.3/src/lib.rs API
// This is how to dynamically select the backend at runtime

use keyring::{set_default_credential_builder, Entry};

#[cfg(all(target_os = "linux", feature = "linux-native"))]
fn use_keyutils_backend() {
    // Switch to keyutils backend for headless Linux
    set_default_credential_builder(
        keyring::keyutils::default_credential_builder()
    );
}

#[cfg(all(target_os = "linux", feature = "sync-secret-service"))]
fn use_secret_service_backend() {
    // Default when both features enabled; explicit for clarity
    set_default_credential_builder(
        keyring::secret_service::default_credential_builder()
    );
}
```

### Probe Pattern for Backend Detection

```rust
// Source: design from keyring Entry API
const PROBE_KEY: &str = "unix-oidc-probe";
const PROBE_SERVICE: &str = "unix-oidc-agent";
const PROBE_VALUE: &[u8] = b"probe-ok";  // non-empty required by keyutils

fn probe_backend(entry_fn: impl Fn() -> Result<Entry, keyring::Error>)
    -> Result<(), StorageError>
{
    let entry = entry_fn()
        .map_err(|e| StorageError::Backend(e.to_string()))?;

    // Write
    let encoded = base64::engine::general_purpose::STANDARD.encode(PROBE_VALUE);
    entry.set_password(&encoded)
        .map_err(|e| StorageError::Backend(e.to_string()))?;

    // Read
    entry.get_password()
        .map_err(|e| StorageError::Backend(e.to_string()))?;

    // Delete (clean up)
    entry.delete_credential()
        .map_err(|e| StorageError::Backend(e.to_string()))?;

    Ok(())
}
```

### Headless CI Test Pattern (Docker without D-Bus)

```dockerfile
# Mask D-Bus socket to simulate headless environment
# Source: Docker docs — masking system sockets
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libdbus-1-dev keyutils
# D-Bus not running in container by default; no dbus-daemon started
# unix-oidc-agent probe will fail Secret Service → fall to keyutils
```

```rust
// Integration test pattern
// Source: design; run with cargo test --test headless_storage_test
#[test]
#[cfg(target_os = "linux")]
fn test_headless_fallback_to_keyutils() {
    // Ensure D-Bus is not available (set env to prevent fallthrough)
    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "");

    let router = StorageRouter::detect().expect("detect should succeed");
    assert!(matches!(router.kind, BackendKind::KeyutilsUser),
        "expected keyutils fallback, got {:?}", router.kind);

    // Store and retrieve a test credential
    let value = b"test-key-material";
    router.store("test-key", value).expect("store should work");
    let retrieved = router.retrieve("test-key").expect("retrieve should work");
    assert_eq!(retrieved, value);
    router.delete("test-key").ok();
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `FileStorage` hardcoded everywhere | `StorageRouter` with probe-based selection | Phase 2 (now) | All command paths use best available backend |
| `keyring = "3"` (mock on Linux) | `keyring` with `sync-secret-service` + `linux-native` | Phase 2 (now) | Actual D-Bus and keyutils backends enabled |
| `load_or_create_signer(&FileStorage)` | `load_or_create_signer(&dyn SecureStorage)` | Phase 2 (now) | Works with any backend |
| No storage info in `status` | `Storage: keyring (Secret Service)` etc. | Phase 2 (now) | Operators can verify backend in use |

**Deprecated/outdated:**
- Direct `FileStorage::new()` at 7 call sites: will be replaced by `StorageRouter::detect()`
- Hardcoded `FileStorage` type in `load_or_create_signer` signature: will change to `&dyn SecureStorage`

---

## Open Questions

1. **keyutils persistent keyring actual behavior under SSH session exit**
   - What we know: `keyutils.rs` in `keyring-3.6.3` obtains `KeyRing::get_persistent(KeyRingIdentifier::Session)` and links keys to it. The persistent keyring survives session exit.
   - What's unclear: Whether `get_persistent()` ever returns `None` in CI Docker containers with a Linux kernel that supports keyutils. If `persistent` is `None`, only `@s` is used and credentials die on session exit.
   - Recommendation: Plan 02-01 spike must explicitly check `KeyutilsCredential.persistent` is `Some(...)` AND verify persistence across `keyctl new_session`.

2. **`set_default_credential_builder` thread safety**
   - What we know: It's a global mutable setter (`static mut` or `OnceLock` internally). The keyring crate docs note "thread-safe code, but underlying stores may not handle access from different threads reliably."
   - What's unclear: Is it safe to call `set_default_credential_builder` after any `Entry::new()` has already been called (e.g., from a previous probe attempt)?
   - Recommendation: Call `set_default_credential_builder` once at process start, before any `Entry::new()` call. The probe functions should use `Entry::new_with_credential()` directly with the concrete builder to avoid touching the global default.

3. **`sync-secret-service` build dependency on CI**
   - What we know: Requires `libdbus-1-dev` to compile.
   - What's unclear: Whether the existing `ubuntu-latest` runner has it installed.
   - Recommendation: Add `libdbus-1-dev` to `ci.yml` install step. Verify compilation doesn't fail before proceeding.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in (`cargo test`), edition 2021 |
| Config file | none — `[dev-dependencies]` in `Cargo.toml` |
| Quick run command | `cargo test -p unix-oidc-agent` |
| Full suite command | `cargo test --all-features` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| STOR-01 | Probe write/read/delete cycle completes successfully on available backend | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_probe_cycle` | ❌ Wave 0 |
| STOR-01 | Probe failure returns correct error variant | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_probe_failure` | ❌ Wave 0 |
| STOR-02 | FileStorage fallback when all keyring probes fail | unit (mock) | `cargo test -p unix-oidc-agent storage::router::tests::test_fallback_to_file` | ❌ Wave 0 |
| STOR-02 | Seven FileStorage::new() call sites replaced — no regression | unit/compile | `cargo build -p unix-oidc-agent` | existing |
| STOR-03 | Migration moves all 4 keys to keyring, file keys deleted | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_success` | ❌ Wave 0 |
| STOR-03 | Migration rollback on key 3 failure: keys 1+2 removed from keyring | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_rollback` | ❌ Wave 0 |
| STOR-03 | Migration skipped when no file credentials exist | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_noop` | ❌ Wave 0 |
| STOR-04 | Headless: keyutils backend selected when D-Bus absent | integration (CI only) | `cargo test -p unix-oidc-agent --test headless_storage -- --ignored` | ❌ Wave 0 |
| STOR-04 | Credentials survive simulated session restart (stop + start) | integration (CI only) | (above test includes restart simulation) | ❌ Wave 0 |
| STOR-05 | File deletion uses secure_remove during migration | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_uses_secure_delete` | ❌ Wave 0 |
| STOR-06 | `status` reports correct backend string | unit | `cargo test -p unix-oidc-agent daemon::protocol::tests::test_status_storage_backend` | ❌ Wave 0 |
| STOR-07 | Documentation exists (manual check) | manual | inspect `docs/` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p unix-oidc-agent`
- **Per wave merge:** `cargo test --all-features`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `unix-oidc-agent/src/storage/router.rs` — `StorageRouter` struct, `detect()`, migration logic
- [ ] `unix-oidc-agent/src/storage/router.rs` tests — unit tests for probe, fallback, migration, rollback
- [ ] `unix-oidc-agent/tests/headless_storage.rs` — integration test with `#[ignore]` for CI Docker path
- [ ] `unix-oidc-agent/Cargo.toml` — add `sync-secret-service`, `linux-native`, `apple-native` to `keyring` features
- [ ] `unix-oidc-agent/Cargo.toml` `[dev-dependencies]` — no additions needed (tempfile already present)
- [ ] `.github/workflows/ci.yml` — add `libdbus-1-dev` to apt install step

---

## Sources

### Primary (HIGH confidence)
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/keyring-3.6.3/src/keyutils.rs` — direct source inspection: session + persistent keyring usage, `KeyRingIdentifier::Session`, `get_persistent()` behavior
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/keyring-3.6.3/src/keyutils_persistent.rs` — direct source: combo store design
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/keyring-3.6.3/src/lib.rs` — direct source: feature flag documentation, `set_default_credential_builder`, mock fallback condition
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/keyring-3.6.3/Cargo.toml` — direct source: feature flag names and dependency tree
- `unix-oidc-agent/src/storage/mod.rs`, `keyring_store.rs`, `file_store.rs`, `secure_delete.rs` — existing code audit
- `unix-oidc-agent/src/main.rs` — all 6 `FileStorage::new()` call sites identified and characterized
- `unix-oidc-agent/src/daemon/socket.rs` — 7th `FileStorage::new()` call site
- `unix-oidc-agent/Cargo.toml` — CONFIRMED: `keyring = "3"` has no features (mock store on Linux)

### Secondary (MEDIUM confidence)
- `keyring` crate docs (module-level doc comments in source) — persistence behavior under SSH logout
- `.github/workflows/ci.yml` — existing CI build steps, apt packages installed

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified directly from crate source files in cargo registry
- Architecture: HIGH — `SecureStorage` trait and existing patterns fully understood from source
- Pitfalls: HIGH for features/mock issue (confirmed), MEDIUM for keyutils persistence (requires spike validation)

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (keyring 3.6.3 is locked in Cargo.lock; no expiry concern for 30 days)
