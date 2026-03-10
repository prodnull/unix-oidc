# Roadmap: unix-oidc Client-Side Key Protection Hardening

## Overview

Three phases close the primary threat model gap in the unix-oidc agent: DPoP private keys currently live as plaintext bytes on disk and in unprotected heap memory. Phase 1 hardens memory (zeroization, mlock, secure deletion) without touching storage APIs. Phase 2 activates the dormant keyring backend as the default storage path, including headless fallback and migration of existing file-stored credentials. Phase 3 adds optional hardware signer backends (YubiKey via PKCS#11, TPM via tss-esapi) behind Cargo feature flags. Phases execute in strict dependency order: Phase 2 requires Phase 1's `Zeroizing<Vec<u8>>` export paths to exist before keyring writes; Phase 3 requires Phase 2's storage path to be stable before hardware metadata writes.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Memory Protection Hardening** - Wrap key material in zeroize/mlock/secrecy; replace naive file deletion with random-overwrite
- [ ] **Phase 2: Storage Backend Wiring** - Activate keyring as default storage with headless fallback chain and file-to-keyring migration
- [ ] **Phase 3: Hardware Signer Backends** - Add YubiKey (PKCS#11) and TPM signer implementations behind optional Cargo features

## Phase Details

### Phase 1: Memory Protection Hardening
**Goal**: Key material is zeroized on drop, locked against swap exposure, and wiped from disk with overwrite semantics
**Depends on**: Nothing (first phase)
**Requirements**: MEM-01, MEM-02, MEM-03, MEM-04, MEM-05, MEM-06
**Success Criteria** (what must be TRUE):
  1. When the agent process exits or a `SigningKey` is dropped, the key bytes are zeroed in memory (verifiable via `p256` `zeroize` feature + `ZeroizeOnDrop` derive; confirmed by unit test asserting memory contents after drop)
  2. Agent daemon startup calls `secmem-proc` to disable core dumps, and key material pages are pinned via `mlock` — the daemon logs the mlock outcome at INFO level on startup
  3. An OAuth token (access, refresh, client secret) printed via `tracing::debug!` or `{:?}` appears as `[REDACTED]` rather than the raw value, because tokens are wrapped in `secrecy::Secret<String>`
  4. Running `unix-oidc-agent` on a system with existing file-stored credentials and then deleting them produces a random-overwrite + fsync + unlink sequence (not a simple file remove), and the agent logs a CoW advisory warning on btrfs/APFS
  5. The security rationale for memory protection decisions (mlock semantics, zeroize limitations, secrecy wrapper) is present in CLAUDE.md security invariants and the README security section
**Plans**: 3 plans (2 waves)

Plans:
- [x] 01-01: Add `zeroize` + `secrecy` to workspace; enable `p256` `zeroize` feature; wrap `SigningKey` in `ProtectedSigningKey` with `ZeroizeOnDrop` and `Option<MlockGuard>`
- [x] 01-02: Wrap all `export_key()` return paths in `Zeroizing<Vec<u8>>`; wrap access/refresh/client-secret fields in `secrecy::Secret<String>`; add `secmem-proc` call at daemon startup
- [ ] 01-03: Replace `FileStorage::delete()` with random-overwrite + fsync + unlink; add CoW advisory log; update CLAUDE.md and README security sections

### Phase 2: Storage Backend Wiring
**Goal**: The agent defaults to OS keyring storage, falls back to kernel keyutils on headless Linux, migrates existing file-stored credentials transparently, and reports its active backend on status
**Depends on**: Phase 1
**Requirements**: STOR-01, STOR-02, STOR-03, STOR-04, STOR-05, STOR-06, STOR-07
**Success Criteria** (what must be TRUE):
  1. On a desktop Linux system with D-Bus Secret Service (GNOME Keyring / KWallet) running, starting the agent stores the DPoP key and tokens in the OS keyring — confirmed by querying the keyring directly and observing no plaintext files in `~/.local/share/unix-oidc-agent/`
  2. On a headless Linux server without D-Bus, the agent falls back to the kernel user keyring (`@u`, not `@s`) automatically — the agent logs "keyring unavailable, falling back to keyutils user keyring" at INFO — and credentials survive an SSH session logout without regenerating a new DPoP key
  3. An existing installation with file-stored credentials (`~/.local/share/unix-oidc-agent/unix-oidc-dpop-key` etc.) starts the agent, which transparently migrates credentials to keyring on first successful probe and logs "migrated N credentials from file storage to keyring" — the original files are securely deleted using the Phase 1 overwrite path
  4. `unix-oidc-agent status` outputs the active storage backend ("keyring (Secret Service)", "keyring (keyutils @u)", or "file (fallback)") and migration status ("migrated", "not migrated", "n/a")
  5. CI passes a headless integration test that simulates absent D-Bus and verifies the fallback path activates and credentials persist across a simulated restart
**Plans**: TBD

Plans:
- [ ] 02-01: Validate `keyring` 3.6.3 `keyutils` backend stores to `@u` not `@s` (empirical spike); document finding; implement `StorageRouter::detect()` with probe write/read/delete
- [ ] 02-02: Wire `StorageRouter` into all five `main.rs` command paths replacing hardcoded `FileStorage::new()` calls; implement file-to-keyring migration logic with secure deletion of migrated files
- [ ] 02-03: Implement STOR-04 headless path (`keyutils` `@u` backend); add `unix-oidc-agent status` backend reporting (STOR-06); write headless CI integration test; update storage architecture docs (STOR-07)

### Phase 3: Hardware Signer Backends
**Goal**: Users who require non-exportable key storage can use a YubiKey (via PKCS#11) or TPM 2.0 as the DPoP signer, selected at login via a CLI flag, without affecting users who do not have hardware tokens
**Depends on**: Phase 2
**Requirements**: HW-01, HW-02, HW-03, HW-04, HW-05, HW-06, HW-07
**Success Criteria** (what must be TRUE):
  1. Running `unix-oidc-agent login --signer yubikey:9a` on a system with a connected YubiKey and pcscd running generates and stores a P-256 key on the YubiKey PIV slot 9a, then produces valid DPoP proofs for subsequent SSH sessions — the DPoP private key never leaves the device
  2. Running `unix-oidc-agent login --signer tpm` on a Linux system with TPM 2.0 and tpm2-abrmd running generates a P-256 key in the TPM, produces valid DPoP proofs, and fails with a clear error message if the TPM does not support P-256 ECDSA (capability probe at provisioning time)
  3. Building the agent without any feature flags (`cargo build -p unix-oidc-agent`) succeeds and produces a binary with no YubiKey or TPM dependencies — the hardware features are purely additive optional flags
  4. A YubiKey session opens and closes PCSC per signing operation (no persistent handle held), so running `unix-oidc-agent login` concurrently with `gpg --card-status` does not deadlock or produce PCSC exclusive-lock errors
  5. The hardware key setup guide (YubiKey PIV provisioning, TPM enrollment, PCSC daemon requirements) is present in docs and covers the expected failure modes (PIN lockout, pcscd not running, TPM not present)
**Plans**: TBD

Plans:
- [ ] 03-01: Spike `cryptoki` 0.12.0 `CKM_ECDSA` raw-digest path for DPoP signing; validate JWS encoding round-trip; document findings; implement `YubiKeySigner: DPoPSigner` with open/sign/close PCSC pattern behind `--features yubikey`
- [ ] 03-02: Implement `TpmSigner: DPoPSigner` via `tss-esapi` 7.6.0 behind `--features tpm`; add P-256 capability probe at provisioning time; mandate `tpm2-abrmd` TCTI
- [ ] 03-03: Implement `HardwareSignerFactory` + `SignerConfig` YAML + `--signer` CLI flag (HW-06); write `#[ignore]` hardware integration tests; write hardware key setup docs (HW-07)

## Progress

**Execution Order:**
Phases execute in strict dependency order: 1 → 2 → 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Memory Protection Hardening | 2/3 | In Progress |  |
| 2. Storage Backend Wiring | 0/3 | Not started | - |
| 3. Hardware Signer Backends | 0/3 | Not started | - |
