# Phase 1: Memory Protection Hardening - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Wrap key material in zeroize/mlock/secrecy; replace naive file deletion with random-overwrite. This phase hardens the agent's in-memory and on-disk handling of DPoP private keys and OAuth tokens without changing storage APIs or adding hardware backends.

Requirements: MEM-01, MEM-02, MEM-03, MEM-04, MEM-05, MEM-06

</domain>

<decisions>
## Implementation Decisions

### Secure Delete Behavior
- Three-pass overwrite (DoD 5220.22-M style): random, complement, random — then fsync + unlink
- CoW filesystem advisory: warn at both startup (storage dir check) AND at each delete operation
- SSD/flash advisory: detect block device type via sysfs rotational flag on Linux; log advisory recommending full-disk encryption
- Overwrite failure policy: best-effort — log the overwrite failure, then still unlink the file. Partially-overwritten + unlinked is better than leaving a named file with key material

### mlock Failure Policy
- mlock probe at startup only — test page allocation, log outcome at INFO, warn on EPERM/ENOMEM with mitigation guidance ("increase RLIMIT_MEMLOCK or run as root")
- No per-key-allocation warnings — startup probe determines capability once
- `unix-oidc-agent status` reports mlock state: "Memory protection: mlock active" or "Memory protection: mlock unavailable (reason)"
- Core dump/ptrace disabling via direct `libc::prctl(PR_SET_DUMPABLE, 0)` calls — no secmem-proc crate. Use `#[cfg(target_os)]` for platform-specific branches (Linux: prctl, macOS: PT_DENY_ATTACH)
- mlock scope: key material pages only, not mlockall. Minimal memory footprint, doesn't fight system limits

### ProtectedSigningKey Wrapper Design
- `ProtectedSigningKey` wraps `SigningKey` with zeroize/mlock internally to `SoftwareSigner`
- DPoPSigner trait stays unchanged — protection is an implementation detail of software signers
- `export_key()` returns `Zeroizing<Vec<u8>>` instead of `Vec<u8>` (MEM-01)
- Constructor returns `Box<ProtectedSigningKey>` only — prevents stack copies, stable mlock address (MEM-05)
- `import_key()` goes through `ProtectedSigningKey` directly — key bytes immediately mlocked, input `Zeroizing<Vec<u8>>` zeroized after import

### Secret Redaction Scope
- All three token types wrapped in `Secret<String>`: access_token, refresh_token, client_secret (MEM-03)
- Redact both Debug and Display — no Display impl, force `expose_secret()` for intentional access
- Custom `serde::Serialize` impl that calls `expose_secret()` for storage writes only — clear audit boundary
- Custom `tracing::Value` impl that emits `[REDACTED]` — even TRACE-level logs never show raw token values
- Serialization to JSON metadata: custom serialize exposes for storage; Debug/Display always redacted

### Claude's Discretion
- Exact mlock page size calculations and alignment
- Platform detection strategy for CoW/SSD (best-effort heuristics are acceptable)
- Internal structure of ProtectedSigningKey (whether MlockGuard is Option or always-present)
- Test strategy for verifying zeroization (unsafe memory inspection in tests is acceptable)
- Error type design for secure delete failures

</decisions>

<specifics>
## Specific Ideas

- Three-pass overwrite chosen deliberately over single-pass despite NIST 800-88 recommending single-pass — defense-in-depth preference for key material
- Direct libc calls preferred over secmem-proc crate — fewer dependencies in security-critical path, libc already in workspace
- Box<ProtectedSigningKey> enforced at type level, not just documented — prevents MEM-05 violations at compile time

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `SoftwareSigner` (`unix-oidc-agent/src/crypto/signer.rs`): Current holder of bare SigningKey — will be wrapped with ProtectedSigningKey
- `FileStorage::delete()` (`unix-oidc-agent/src/storage/file_store.rs:85-104`): Currently does zero-overwrite + unlink — needs upgrade to three-pass random + CoW/SSD detection
- `DPoPSigner` trait (`unix-oidc-agent/src/crypto/signer.rs:16-30`): Stays unchanged — ProtectedSigningKey is internal

### Established Patterns
- `thiserror` for error types throughout workspace
- `tracing` for structured logging (INFO/WARN levels for operational events)
- `#[cfg(unix)]` guards for platform-specific code (already used in FileStorage)
- `libc` already a workspace dependency — direct syscall access available

### Integration Points
- `SoftwareSigner::export_key()` → storage layer: return type changes from `Vec<u8>` to `Zeroizing<Vec<u8>>`
- `SoftwareSigner::import_key()` → now constructs ProtectedSigningKey directly
- `main.rs` token handling (~lines 489-510): access_token, refresh_token, client_secret fields need Secret<String> wrapping
- Token metadata JSON serialization (~line 506): needs custom serialize for Secret fields
- Daemon startup (`main.rs`): add mlock probe + prctl(PR_SET_DUMPABLE) before any key material is loaded

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-memory-protection-hardening*
*Context gathered: 2026-03-10*
