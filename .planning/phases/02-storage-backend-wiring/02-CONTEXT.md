# Phase 2: Storage Backend Wiring - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Activate keyring as default storage, fall back to kernel keyutils on headless Linux, then to file storage as last resort. Migrate existing file-stored credentials transparently on first keyring-available startup. Report active backend and migration status via `unix-oidc-agent status`.

Requirements: STOR-01, STOR-02, STOR-03, STOR-04, STOR-05, STOR-06, STOR-07

</domain>

<decisions>
## Implementation Decisions

### Backend Detection & Fallback Chain
- Three-tier fallback order: keyring (D-Bus Secret Service / macOS Keychain) → keyutils @u (Linux headless) → file storage
- Probe mechanism: write/read/delete cycle with a dedicated sentinel key (`unix-oidc-probe`) at startup
- Re-probe every startup — no cached backend selection. Detects environment changes (D-Bus installed/removed, container migration)
- If a previously-used backend becomes unavailable: fall through to next backend, log WARN with actionable message ("credentials from previous backend are inaccessible; run `unix-oidc-agent login` to re-authenticate")
- Environment variable override: `UNIX_OIDC_STORAGE_BACKEND=keyring|keyutils|file` forces a specific backend. Override only takes effect if the forced backend passes the probe

### Migration Behavior
- Auto-migrate on first startup when keyring probe succeeds AND file-stored credentials exist
- Log "migrated N credentials from file storage to keyring" at INFO
- Atomic semantics: if any of the 4 keys fails to migrate, rollback all successfully-migrated keys from keyring and stay on file storage entirely
- After successful migration, verify each key via read-back from keyring, then immediately secure-delete the files using Phase 1's 3-pass DoD overwrite
- Migration scope: file → keyring only. No backend-to-backend upgrades (e.g., keyutils → D-Bus). Upgrade path deferred to ASTOR-02

### Status Reporting
- Default output: backend type + migration status. Examples:
  - `Storage: keyring (Secret Service)` / `Migration: migrated`
  - `Storage: keyring (keyutils @u)` / `Migration: n/a`
  - `Storage: file (fallback)` / `Migration: not migrated`
- Descriptive naming with provider in parentheses: "keyring (Secret Service)", "keyring (keyutils @u)", "keyring (macOS Keychain)", "file (fallback)"
- `--verbose` flag adds diagnostics: probe results for each backend, fallback reason, keyring service name, file storage path
- Human-readable text only for now. No --json output (defer to future phase if scripting needs arise)
- Consistent with Phase 1's mlock status line in the status command

### Headless Session Persistence
- keyutils keys set with no timeout (persist until reboot). Agent manages its own token expiry logic
- No special container detection — the probe chain handles containers naturally (keyring probe fails → keyutils probe fails → file fallback). Log INFO explaining why each probe failed
- CI integration test: Docker container with D-Bus socket masked. Verify credentials persist across simulated process restart (stop daemon, start, check credentials exist)

### Claude's Discretion
- Internal `StorageRouter` struct design and method signatures
- Probe key name and value (suggested: `unix-oidc-probe`)
- keyutils API interaction details (how the `keyring` crate maps to @u vs @s — spike in plan 02-01 determines this)
- Error type extensions to `StorageError` for backend detection failures
- Exact `--verbose` output formatting
- Test fixture design for headless CI test

</decisions>

<specifics>
## Specific Ideas

- Probe sentinel should be distinct from real credential keys to avoid interference
- Migration rollback must clean up keyring entries on failure — don't leave partial state in keyring
- The env var override (`UNIX_OIDC_STORAGE_BACKEND`) still requires probe success — it's a preference, not a force-without-check. If forced backend fails probe, log ERROR and refuse to start (don't silently fall through, since the user explicitly requested a specific backend)

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `SecureStorage` trait (`unix-oidc-agent/src/storage/mod.rs:15-27`): Existing trait with store/retrieve/delete/exists — new `StorageRouter` will implement this trait and delegate to the selected backend
- `KeyringStorage` (`unix-oidc-agent/src/storage/keyring_store.rs`): Fully implemented but not wired up in main.rs. Base64-encodes binary data for keyring compatibility
- `FileStorage` (`unix-oidc-agent/src/storage/file_store.rs`): Active backend with Phase 1's secure delete. Will become fallback
- `secure_delete::secure_remove()` (`unix-oidc-agent/src/storage/secure_delete.rs`): 3-pass DoD overwrite for migrated file cleanup
- Storage key constants (`mod.rs:47-50`): `KEY_DPOP_PRIVATE`, `KEY_ACCESS_TOKEN`, `KEY_REFRESH_TOKEN`, `KEY_TOKEN_METADATA` — the 4 keys to migrate

### Established Patterns
- `thiserror` for error types — extend `StorageError` for detection/migration errors
- `tracing` structured logging — probe results and migration events logged as INFO/WARN
- `#[cfg(unix)]` platform guards — keyutils is Linux-only
- `FileStorage::new()` is called in 7 places (6 in main.rs, 1 in socket.rs) — all need to be replaced with `StorageRouter`

### Integration Points
- `main.rs` lines 242, 315, 560, 595, 730, 762: `FileStorage::new()` calls to replace with `StorageRouter::detect()`
- `daemon/socket.rs` line 404: `FileStorage::new()` in socket handler
- `load_or_create_signer()` at main.rs:810: takes `&FileStorage` — needs to accept `&dyn SecureStorage`
- Status command: already reports mlock state — add storage backend line in the same section

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-storage-backend-wiring*
*Context gathered: 2026-03-10*
