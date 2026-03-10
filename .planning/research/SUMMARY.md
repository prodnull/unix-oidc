# Project Research Summary

**Project:** unix-oidc — Key Protection Hardening Milestone
**Domain:** Client-side OIDC/DPoP agent key storage and memory protection (Rust)
**Researched:** 2026-03-10
**Confidence:** HIGH

## Executive Summary

This milestone hardens the `unix-oidc-agent` against the primary threat model gap: plaintext DPoP private key bytes persisted on disk and resident in unprotected heap memory. The agent already has the right abstractions in place — `DPoPSigner`, `SecureStorage`, `FileStorage`, and a dormant `KeyringStorage` — but none of the security-critical wiring is active. The fix is plumbing, not architecture: activate `KeyringStorage` as the default backend behind a runtime probe, wrap key material in `zeroize` + `mlock`, and replace the naive file deletion path with a filesystem-aware overwrite sequence. All three changes are independently deployable and carry no API surface changes for callers.

The recommended approach follows a strict dependency order: memory protection first (no external dependencies added, no behavior changes, purely additive safety), storage backend wiring second (activates `KeyringStorage`, requires `zeroize` to be in place for key export paths), and hardware signer backends third (optional Cargo features, independent of storage once trait boundaries are stable). The technology choices are conservative: `zeroize` 1.8.2 and `secrecy` 0.10.3 from the RustCrypto ecosystem (already transitive dependencies), `libc::mlock` directly (already a workspace dependency), `keyring` 3.6.3 (already depended on, feature flags adjusted per platform), `cryptoki` 0.12.0 for YubiKey via PKCS#11 (optional), and `tss-esapi` 7.6.0 pinned to stable (optional). The `yubikey` 0.8.0 crate is explicitly rejected — it is unaudited, carries its own experimental warning, and has been stale for 18 months.

The key risk is silent failure modes. On headless Linux servers, `keyring` returns `NoStorageAccess` without D-Bus — if the fallback is not explicit and probed at startup, keys silently fail to persist and the agent generates a new DPoP key on every restart, breaking `cnf` thumbprint continuity for all outstanding tokens. A second risk is the kernel session keyring: if the `keyutils` fallback stores to the session keyring (`@s`) rather than the user keyring (`@u`), keys vanish on SSH logout. Both of these are implementation-time decisions, not architectural unknowns, and the pitfalls research documents the exact prevention strategies for each.

---

## Key Findings

### Recommended Stack

The existing dependency tree already contains most of what is needed. No new heavyweight dependencies are required for the Phase 1 and Phase 2 work. The critical additions are: enabling the `zeroize` feature on the existing `p256 = "0.13"` dependency (a single `Cargo.toml` line), adding `zeroize = "1.8.2"` and `secrecy = "0.10.3"` to the workspace, using `libc::mlock` directly (already present), and adjusting `keyring` 3.6.3's feature flags per platform (`linux-native-sync-persistent` on Linux, `apple-native` on macOS). Hardware backends require `cryptoki = "0.12.0"` (YubiKey via PKCS#11) and `tss-esapi = "7.6.0"` (TPM), both gated behind optional Cargo features. The `p256` crate must stay on `0.13` — the `0.14.x` pre-release removes the `jwk` feature that the agent's `public_key_jwk()` relies on.

**Core technologies:**
- `zeroize` 1.8.2 + `p256` `zeroize` feature: key material zeroed on drop — already the RustCrypto standard, already transitive
- `secrecy` 0.10.3: `Secret<T>` wrapper that redacts Debug output and prevents accidental token/key logging
- `libc::mlock` (direct syscall): prevents key pages from swapping — zero new dependencies
- `keyring` 3.6.3 with `linux-native-sync-persistent`: OS keyring as default storage with headless fallback to kernel keyutils
- `secmem-proc` 0.3.8: `prctl(PR_SET_DUMPABLE, 0)` at daemon startup — prevents `/proc/self/mem` reads and core dump exposure
- `cryptoki` 0.12.0 (optional `yubikey` feature): PKCS#11 path for YubiKey PIV — actively maintained, vendor-supported, generic across PKCS#11 tokens
- `tss-esapi` 7.6.0 (optional `tpm` feature): TPM 2.0 ESAPI bindings — stable release, requires `libtss2-esys` system library

### Expected Features

All research files converge on the same phased priority structure. Phase 1 closes the primary threat gap without any behavior change to callers; subsequent phases are additive.

**Must have (table stakes for this milestone):**
- OS keyring as default storage — `FileStorage` writing raw key bytes to 0600 files is demonstrably inadequate vs. every comparable agent
- Zeroization on key drop — absence is a regression vs. `ssh-agent`, `gpg-agent`, and the rest of the ecosystem
- `mlock` / memory pinning — key pages can reach swap, crash dumps, and hibernation files without it
- Secure credential deletion — current `delete()` is incomplete on CoW filesystems
- Graceful fallback chain — headless servers cannot hard-fail when D-Bus is absent
- Migration path: file to keyring — existing deployments have live keys in `~/.local/share/unix-oidc-agent/`; silent breakage on upgrade is unacceptable

**Should have (competitive differentiators):**
- YubiKey PIV backend (`cryptoki` + PKCS#11) — only agent combining OIDC + DPoP + hardware non-exportable key
- TPM 2.0 backend (`tss-esapi`) — Linux-native hardware binding without YubiKey dependency
- Key TTL / lifetime limit — every comparable agent limits the credential exposure window
- Filesystem CoW detection and advisory warning — honest and actionable for users on btrfs/APFS
- Per-signing-op structured audit events — carries thumbprint + target, satisfies PAM non-repudiation requirements

**Defer to future milestones:**
- Token-bound key rotation — requires token refresh redesign; high value, high complexity
- PKCS#11 general backend (evaluate as superseding YubiKey/TPM bespoke backends first)
- FIDO2 / `authenticator-rs` — CTAP2 assertion flows do not map cleanly to DPoP proof generation without significant protocol work
- Networked credential sync — out of scope by design; DPoP proof-of-possession requires per-device key residency

### Architecture Approach

The existing trait boundaries are correct and require no changes. The work is wiring. A new `StorageRouter` component performs a runtime probe at agent startup to select between `KeyringStorage` (primary) and `FileStorage` (fallback), replacing the five hardcoded `FileStorage::new()` calls in `main.rs`. A `ProtectedSigningKey` struct wraps `p256::ecdsa::SigningKey` with an `Option<MlockGuard>` that calls `munlock` on drop; this replaces the raw `SigningKey` field in `SoftwareSigner`. `HardwareSignerFactory` dispatches to software, YubiKey, or TPM backends based on `SignerConfig` from the agent's YAML. The `SecureFileDelete` pattern in `FileStorage::delete()` replaces zero-fill with random-overwrite + `fsync` + `unlink`, with a structured log warning on CoW filesystems.

**Major components:**
1. `StorageRouter` — runtime probe selects `KeyringStorage` or `FileStorage`; performs file-to-keyring migration on first successful probe
2. `ProtectedSigningKey` — wraps `SigningKey` with `ZeroizeOnDrop` (via `p256` `zeroize` feature) and `Option<MlockGuard>` for swap prevention
3. `SecureFileDelete` — random-overwrite + `fsync` + `unlink` in `FileStorage::delete()`; CoW advisory log
4. `HardwareSignerFactory` — constructs `Arc<dyn DPoPSigner>` from `SignerConfig`; dispatches to `SoftwareSigner`, `YubiKeySigner`, or `TpmSigner`

### Critical Pitfalls

1. **Keyring activation breaks headless deployments silently** — `keyring` v3 returns `NoStorageAccess` on servers without D-Bus, not a panic. If the fallback is not explicitly probed at startup, the agent proceeds silently without persisting keys, generates a new DPoP key on next restart, and breaks `cnf` thumbprint continuity for all outstanding tokens. Prevention: implement backend probe at daemon startup; fall back to `keyutils` backend (kernel keyring, no D-Bus required); log the selected backend at `INFO` level.

2. **Kernel session keyring evicts keys on SSH logout** — if the `keyutils` fallback stores to `@s` (session keyring), PAM evicts it on logout. Store to the user keyring (`@u`) instead; it persists across SSH sessions as long as any process with that UID is alive.

3. **`mlock` on a `Vec<u8>` does not lock what you think** — any `Vec::push()` or reallocation moves the data to a new, unlocked page; the old page retains an unprotected copy of the key. Fix buffer size before locking; convert to `Box<[u8]>` via `.into_boxed_slice()` before calling `mlock`.

4. **`zeroize` move semantics leave unzeroized stack copies** — Rust's move semantics `memcpy` struct bytes to the new stack location without zeroing the source. `Zeroizing<T>` only zeroes the final resting place. Pass raw key bytes by `&mut` reference across function boundaries; keep `SigningKey` heap-resident in an `Arc` once constructed.

5. **`p256` `zeroize` feature off by default silently breaks `ZeroizeOnDrop`** — `#[derive(ZeroizeOnDrop)]` on a struct containing `SigningKey` does nothing if `p256` was not compiled with `features = ["zeroize"]`. The derive compiles without error. Prevention: explicitly declare `p256 = { version = "0.13", features = ["ecdsa", "jwk", "zeroize"] }` in `Cargo.toml`.

---

## Implications for Roadmap

Based on the combined research, there is strong consensus across all four files on a 3-phase structure. Phase ordering is strictly determined by implementation dependencies, not arbitrary grouping.

### Phase 1: Memory Protection Hardening

**Rationale:** Zero external dependencies added, no interface changes, no migration risk. All existing tests continue to pass. This phase must land first because Phase 2's storage write paths need `Zeroizing<Vec<u8>>` wrapping for key export — if Phase 2 lands without it, key bytes leak to heap on every keyring write.

**Delivers:** `SoftwareSigner` with `ZeroizeOnDrop` on the signing key; `Zeroizing<Vec<u8>>` wrapping every `export_key()` call site; `ProtectedSigningKey` struct with `Option<MlockGuard>`; `FileStorage::delete()` using random-overwrite + `fsync` + `unlink`; `secmem-proc` call at daemon startup.

**Addresses:** Table-stakes features: zeroization on drop, mlock/memory pinning, secure credential deletion.

**Avoids:** Pitfall 5 (move semantics leaving stack copies), Pitfall 6 (`p256` zeroize feature silently off), Pitfall 4 (mlock on growable `Vec`), Pitfall 7 (drop ordering exposing key material).

**Research flag:** Standard patterns, well-documented. No additional research phase needed.

---

### Phase 2: Storage Backend Wiring

**Rationale:** Requires Phase 1 (key export paths must already be `Zeroizing`-wrapped before activating keyring writes). This is the highest-value phase — it moves the default storage from plaintext files to OS-managed protected storage, which is the primary threat model gap.

**Delivers:** `StorageRouter::detect()` with startup probe; all five `main.rs` command paths use `StorageRouter` instead of hardcoded `FileStorage`; file-to-keyring migration logic; `secmem-proc` startup call; integration tests for fallback path (headless, D-Bus absent); `FileStorage` CoW advisory log; macOS CI using mock Keychain backend.

**Uses:** `keyring` 3.6.3 with `linux-native-sync-persistent` (Linux) and `apple-native` (macOS); `secrecy` 0.10.3 for in-memory token storage.

**Implements:** `StorageRouter` component, `SecureFileDelete` improvements.

**Avoids:** Pitfall 1 (silent storage failure on headless), Pitfall 2 (session keyring eviction on logout), Pitfall 12 (CoW filesystem retains plaintext after deletion), Pitfall 13 (macOS Keychain prompt blocks CI).

**Research flag:** Keyring fallback behavior requires careful validation. The `#[ignore]` tests on `KeyringStorage` are a warning sign — the probe-and-fallback logic should be exercised in CI with explicit headless simulation before merge.

---

### Phase 3: Hardware Signer Backends

**Rationale:** Independent of Phase 2 (hardware backends never call `SecureStorage` — keys never leave the device), but should land after Phase 2 so the storage path is stable before introducing hardware complexity. These are optional Cargo features; existing deployments are unaffected.

**Delivers:** `YubiKeySigner: DPoPSigner` behind `--features yubikey` (via `cryptoki` 0.12.0 + YKCS11); `TpmSigner: DPoPSigner` behind `--features tpm` (via `tss-esapi` 7.6.0); `HardwareSignerFactory`; `SignerConfig` in agent YAML (`backend: software|yubikey:9a|tpm`); `#[ignore]` integration tests requiring physical hardware.

**Avoids:** Pitfall 8 (PCSC exclusive lock blocking gpg-agent — open/close per operation, cache PIN in-process), Pitfall 9 (pcscd stale after resume — retry loop in `YubiKey::open()`), Pitfall 10 (TPM direct access blocks concurrent processes — mandate `tpm2-abrmd` TCTI), Pitfall 11 (YubiKey firmware version assumptions), Pitfall 14 (PIN retry exhaustion — one attempt per prompt, surface retry count).

**Research flag:** Hardware backend phases warrant a focused research pass during planning. The `yubikey` 0.8.0 crate is rejected; the `cryptoki` 0.12.0 PKCS#11 path needs a small proof-of-concept before committing to DPoP signing integration, specifically to validate `CKM_ECDSA` raw-digest signing behavior against the JWS signing input. TPM P-256 ECDSA capability varies by device — require a capability probe at provisioning time.

---

### Phase Ordering Rationale

- Phase 1 before Phase 2: `export_key()` must return `Zeroizing<Vec<u8>>` before keyring write paths exist; otherwise key bytes leak to heap on every storage operation.
- Phase 2 before Phase 3: hardware backends store per-device metadata (slot configuration, TPM handle indices) in `SecureStorage`; storage path must be stable before adding hardware metadata writes.
- Hardware features are optional and additive — they do not block Phase 1 or Phase 2 from shipping to users.
- File-to-keyring migration is part of Phase 2, not a separate phase — it must be atomic with keyring activation to avoid a window where both backends are active and keys are duplicated.

### Research Flags

Phases needing deeper research or validation during planning:

- **Phase 2 (Storage Backend Wiring):** Validate `keyring` 3.6.3 `keyutils` backend stores to user keyring (`@u`), not session keyring (`@s`), before finalising the fallback implementation. The dormant `KeyringStorage` has never been exercised in CI — treat it as functionally untested.
- **Phase 3 (Hardware Backends):** `cryptoki` 0.12.0 `CKM_ECDSA` raw-digest signing path needs a proof-of-concept before integration. TPM P-256 capability probe strategy needs design. PCSC transaction management (open/close per operation vs. persistent) needs an explicit architecture decision before any code is written.

Phases with standard patterns (skip research-phase):

- **Phase 1 (Memory Protection):** `zeroize`, `mlock`, `ZeroizeOnDrop` are well-documented RustCrypto patterns with authoritative crate documentation. Implementation is mechanical.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All crates verified via crates.io API on 2026-03-10; version pinning rationale documented; `p256` 0.14.x pre-release rejection is well-founded |
| Features | HIGH | Based on direct codebase inspection plus authoritative primary sources for competitor agents (1Password, Secretive, Teleport, yubikey-agent official docs) |
| Architecture | HIGH | Ground truth from codebase inspection (`storage/mod.rs`, `crypto/signer.rs`, `main.rs`); proposed components have no speculative dependencies |
| Pitfalls | HIGH | Sourced from official man pages (mlock, session-keyring, user-keyring), keyring-rs issue tracker, official Yubico docs, NIST SP 800-88 Rev. 1 |

**Overall confidence:** HIGH

### Gaps to Address

- **`keyring` 3.6.3 `keyutils` user-keyring vs. session-keyring behavior:** The research identifies this as a risk (Pitfall 2) and references the `keyutils` backend docs, but the exact storage key path (`@u` vs. `@s`) should be confirmed empirically in a test environment before the Phase 2 PR is written.
- **`cryptoki` 0.12.0 DPoP signing correctness:** The PKCS#11 path using `CKM_ECDSA` (raw digest, not `CKM_ECDSA_SHA256`) for DPoP proof generation has not been prototyped. A one-day spike to validate the mechanism + JWS encoding round-trip before committing to the full implementation.
- **TPM P-256 ECDSA capability breadth:** `tss-esapi` 7.6.0 supports P-256, but capability support in real TPM 2.0 chips varies. Cloud vTPMs (AWS, GCP, Azure) should be tested in addition to physical TPMs during the hardware phase.
- **`tss-esapi` 8.x upgrade path:** 8.0.0-alpha.2 adds the `bundled` feature (vendors `tpm2-tss`, eliminating the system library dependency) which materially improves deployment story. Track the 8.x release and plan a follow-on milestone upgrade once it stabilises.

---

## Sources

### Primary (HIGH confidence)

- crates.io API — keyring 3.6.3, zeroize 1.8.2, cryptoki 0.12.0, tss-esapi 7.6.0, secrecy 0.10.3, secmem-proc 0.3.8 (all fetched 2026-03-10)
- RFC 9449 — DPoP (Demonstrating Proof of Possession): https://www.rfc-editor.org/rfc/rfc9449
- NIST SP 800-88 Rev. 1, "Guidelines for Media Sanitization" (December 2014)
- mlock(2) Linux man page: https://man7.org/linux/man-pages/man2/mlock.2.html
- session-keyring(7) Linux man page: https://www.man7.org/linux/man-pages/man7/session-keyring.7.html
- user-keyring(7) Linux man page: https://man7.org/linux/man-pages/man7/user-keyring.7.html
- 1Password SSH agent security model: https://developer.1password.com/docs/ssh/agent/security/
- Secretive project: https://secretive.dev/, https://github.com/maxgoedjen/secretive
- Teleport hardware key support: https://goteleport.com/docs/zero-trust-access/authentication/hardware-key-support/
- yubikey-agent: https://github.com/FiloSottile/yubikey-agent
- Yubico PIV PIN/touch policies: https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html
- tpm2-abrmd: https://github.com/tpm2-software/tpm2-abrmd
- RustCrypto elliptic-curve `ZeroizeOnDrop` on `SecretKey`
- keyring-rs docs (Linux backends): https://docs.rs/keyring/latest/keyring/

### Secondary (MEDIUM confidence)

- OpenSSH shielded private key analysis: https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/
- zeroize move semantics pitfall: https://benma.github.io/2020/10/16/rust-zeroize-move.html
- Docker + RLIMIT_MEMLOCK (container environments): https://medium.com/@thejasongerard/resource-limits-mlock-and-containers-oh-my-cca1e5d1f259
- Smallstep cryptographic protection: https://smallstep.com/docs/step-ca/cryptographic-protection/
- Teleport hardware key PIN caching PR: https://github.com/gravitational/teleport/pull/54297

### Tertiary (LOW confidence — needs implementation validation)

- `cryptoki` PKCS#11 `CKM_ECDSA` raw-digest behavior for DPoP proof signing: needs prototype
- `keyring` 3.6.3 `keyutils` backend storing to `@u` vs. `@s`: needs empirical confirmation

---

*Research completed: 2026-03-10*
*Ready for roadmap: yes*
