# Domain Pitfalls: Client-Side Key Protection in Rust

**Domain:** OIDC agent — keyring integration, memory protection, secure deletion, hardware key support
**Researched:** 2026-03-10
**Milestone:** Key Protection Hardening (unix-oidc-agent)

---

## Critical Pitfalls

Mistakes that cause data exposure, silent credential loss, or production breakage.

---

### Pitfall 1: Keyring Activation Breaks Headless Deployments Silently

**What goes wrong:** `keyring` v3 on Linux defaults to the Secret Service backend (D-Bus + gnome-keyring or KWallet). On headless servers, CI runners, and containers, the D-Bus session bus is absent or has no Secret Service daemon attached. The call to `Entry::new()` or `set_password()` returns an opaque error. If the caller pattern-matches only on "success or file fallback" without explicitly catching backend-unavailable errors, credentials silently fail to store — the agent proceeds as if storage succeeded.

**Why it happens:** `keyring` v3 changed its Linux backend selection. The prior behavior of falling back automatically is not guaranteed; the crate surfaces a `NoStorageAccess` or D-Bus connection error that must be explicitly handled by the caller. The dormant `KeyringStore` in this codebase (`storage/keyring_store.rs`) likely does not yet implement this fallback path (the existing tests are marked `#[ignore]`).

**Consequences:**
- Agent appears functional; DPoP key is never persisted to secure storage
- On next restart, `load_or_create_signer()` generates a *new* key, breaking DPoP continuity — all outstanding tokens bound to the old key's `cnf` thumbprint are invalid
- No user-visible error; silent identity rotation

**Prevention:**
1. Use `keyring`'s `keyutils` backend as the primary fallback on Linux headless environments (kernel keyring; no D-Bus required; ships in all distro kernels ≥ 4.0).
2. Implement backend probe at agent startup: attempt Secret Service → fall back to `keyutils` → fall back to `FileStorage`. Log which backend was selected at `INFO` level.
3. Make the backend probe a startup check, not a lazy first-write check, so failures are immediately visible.
4. For CI: add a test target that explicitly sets `KEYRING_BACKEND=keyutils` (or a mock) and runs the full storage round-trip.

**Warning signs:**
- `#[ignore]` tests on `KeyringStore` — the backend has never been exercised in automation
- Agent starts cleanly but generates a new keypair on every restart

**Phase mapping:** Phase activating the keyring backend (wiring `KeyringStore` into `load_agent_state()`). Must be addressed before merge.

---

### Pitfall 2: Kernel `keyutils` Session Keyring Disappears on SSH Logout

**What goes wrong:** If the fallback path uses the Linux kernel session keyring (`@s`), keys stored there are scoped to the user's PAM session. When the user logs out of their last SSH session, PAM calls `keyctl_revoke()` on the session keyring — all stored keys vanish. On next login, `load_or_create_signer()` again generates a new DPoP key, breaking the `cnf` thumbprint.

**Why it happens:** The session keyring (`man 7 session-keyring`) is designed for ephemeral session state; `pam_keyinit(8)` creates and revokes it on login/logout. This is the correct behavior for session-scoped secrets, but wrong for a DPoP private key that is meant to persist across sessions.

**Consequences:** Same silent key rotation as Pitfall 1 but triggered by normal logout/login cycles.

**Prevention:**
- Store the DPoP private key in the *user keyring* (`@u`), not the session keyring. The user keyring persists as long as any process running as that UID is alive (i.e., across SSH sessions).
- `keyring` v3's `keyutils` backend stores to the user keyring by default — verify this in the `keyring::keyutils` backend documentation before finalizing the implementation.
- Alternatively, use the Secret Service with the `login` collection (unlocked at login and persisted across sessions) if D-Bus is available.

**Warning signs:** DPoP key changes after every SSH session end/start, observable by checking the key thumbprint in stored tokens.

**Phase mapping:** Same phase as Pitfall 1 (keyring activation). Needs an explicit integration test simulating session teardown.

---

### Pitfall 3: `mlock` Silently Fails or Is Skipped in Containers and CI

**What goes wrong:** `libc::mlock()` on an unprivileged process is bounded by `RLIMIT_MEMLOCK`. On most Linux distributions the default soft limit for non-root users is 64 KiB (verified in Docker/container discussions; Elasticsearch, llama.cpp, and Cassandra deployments all document hitting exactly this limit). An agent trying to lock more than 64 KiB of heap — or any memory in a rootless Docker/Kubernetes environment without `CAP_IPC_LOCK` — will receive `ENOMEM`. If the code treats `mlock` failure as fatal, the agent refuses to start. If it silently ignores the error, key material is unprotected without any indication.

**Why it happens:**
- Docker containers run without `CAP_IPC_LOCK` by default
- Rootless Docker/Podman cannot raise `RLIMIT_MEMLOCK` beyond the host's hard limit for the user
- CI runners (GitHub Actions, GitLab CI) run as unprivileged users with default limits

**Consequences:**
- If fatal: agent won't start in any CI or container environment — blocks automated testing
- If silently ignored: `mlock` protection is theater; key material can still be paged to swap

**Prevention:**
1. Treat `mlock` as best-effort. Log a `WARN` with the `ENOMEM` detail if it fails; do not abort.
2. Check `RLIMIT_MEMLOCK` at startup and log the effective limit so operators know their protection level.
3. For page alignment: `mlock()` operates on whole pages. When calling it on heap-allocated buffers (e.g., a `Box<[u8; 32]>` for the raw key bytes), the page containing the buffer may also contain unrelated data — this is acceptable but means the lock covers more than just the key. Use `memsec` or `secrets` crates which handle alignment and guard pages correctly rather than calling `libc::mlock` directly.
4. Test the `mlock`-unavailable code path explicitly in CI (do not skip or `#[ignore]` it — verify the fallback behavior is correct).

**Warning signs:** Any `mlock` call without a checked return value; absence of test coverage for the `ENOMEM` path.

**Phase mapping:** Phase adding `mlock` protection. The `ENOMEM` fallback path must be tested before merge.

---

### Pitfall 4: `mlock` on a `Vec<u8>` Doesn't Lock What You Think

**What goes wrong:** Calling `mlock` on the pointer inside a `Vec<u8>` locks the current heap allocation. However:
- `Vec::push()`, `Vec::reserve()`, or any operation that causes reallocation moves the data to a new, unlocked page. The old page is not zeroed; it contains a copy of the key.
- `Box<[u8]>` avoids reallocation after construction but still has no alignment guarantee: the allocation may share a page with other heap data, causing the lock to cover more than intended (benign) or — if using a locked allocator — to lock non-secret data.

**Why it happens:** `Vec` is a growable container; its internal buffer can move. `mlock` on the address at time-of-call does not follow the data if it moves.

**Consequences:** Key material exists in unlocked, potentially swappable memory after any Vec growth operation.

**Prevention:**
- Fix the buffer size before locking: convert to `Box<[u8; N]>` or `Box<[u8]>` (via `.into_boxed_slice()`) before calling `mlock`. Never call `mlock` on a `Vec` that is still growable.
- Prefer `memsec::malloc_arr::<u8>(N)` or the `secrets` crate's `SecretVec`, which allocates a fixed-size, page-aligned, mlock'd buffer from the start. These also add guard pages to detect over/underflows.
- For the P-256 `SigningKey` (32 bytes of scalar): wrap in `Zeroizing<[u8; 32]>` for serialization/deserialization buffers; the in-memory `SigningKey` struct from the `p256` crate already implements `ZeroizeOnDrop` (verify with the installed version).

**Warning signs:** `mlock` called on a `Vec<u8>` that was grown after construction; no guard for reallocation.

**Phase mapping:** Same phase as `mlock` addition. Architecture review item before implementation starts.

---

### Pitfall 5: `zeroize` Cannot Zero Copies Created by Move Semantics

**What goes wrong:** Rust's move semantics compile to a `memcpy` of the struct's bytes to the new stack location. The source bytes on the old stack frame are *not* zeroed — the compiler only guarantees they are not accessible by the moved-from name, not that the memory is cleared. `Zeroizing<T>` zeroes the final resting place on `Drop`, but all intermediate copies created by passing the value between functions remain uncleared.

Concrete scenario for this codebase: `load_or_create_signer()` reads 32 raw key bytes from storage into a `Vec<u8>`, passes it to `SigningKey::from_bytes()`, and the intermediate buffer accumulates multiple stack frames before being zeroed.

**Why it happens:** Rust does not have a "move-and-wipe-source" semantic. This is a known, open language-level limitation — the `Pin` RFC and various proposals have not resolved it as of 2026.

**Consequences:** Multiple copies of the raw key scalar exist on the stack after deserialization, surviving until those stack frames are overwritten by subsequent function calls. This is exploitable via core dump analysis, `/proc/self/mem` inspection by same-UID processes (the exact threat model this milestone is trying to close), and cold boot attacks.

**Prevention:**
1. Minimize the number of by-value moves of key material. Pass raw key bytes as `&mut [u8]` (by mutable reference) whenever possible so the data stays in one memory location.
2. Use `Zeroizing<[u8; 32]>` (stack-fixed-size array) for the deserialization buffer, not `Vec<u8>`. Fixed-size arrays passed by value still copy, but the single-location discipline is easier to audit.
3. Prefer keeping the P-256 `SigningKey` in an `Arc<Zeroizing<SigningKey>>` (heap, single owner) throughout the agent's lifetime so it is never moved once constructed.
4. After calling `SigningKey::from_bytes()` or equivalent, immediately call `.zeroize()` on the input buffer and ensure the buffer is declared with `zeroize::Zeroizing<>` wrapper so `Drop` handles the zero-on-scope-exit case.
5. Do not `clone()` key material structures; if clones are needed, document each one and zeroize explicitly.

**Warning signs:** `SigningKey` or raw key bytes returned by value from functions; `Vec<u8>` used to hold key bytes across multiple function boundaries without being wrapped in `Zeroizing<>`.

**Phase mapping:** Phase adding `zeroize`. Code review checklist item: every function that touches raw key bytes must be audited for intermediate copies.

---

### Pitfall 6: `#[derive(ZeroizeOnDrop)]` Is Silently Incomplete for Wrapper Types

**What goes wrong:** `#[derive(ZeroizeOnDrop)]` on a struct containing a `p256::ecdsa::SigningKey` works only if `SigningKey` itself implements `ZeroizeOnDrop`. The `p256` crate does implement this — but only when compiled with the `zeroize` feature enabled. If the `p256` dependency in `Cargo.toml` does not explicitly opt into `features = ["zeroize"]`, the derive compiles without error but the inner key material is not zeroed on drop.

**Why it happens:** RustCrypto crates gate zeroize support behind a Cargo feature to avoid forcing the `zeroize` crate on all consumers. The feature is often off by default or depends on which `p256` feature set is active.

**Consequences:** Derived `ZeroizeOnDrop` on agent structs gives a false sense of security; the 32-byte private scalar is never zeroed in practice.

**Prevention:**
- In `Cargo.toml`, explicitly declare: `p256 = { version = "0.13", features = ["ecdsa", "zeroize"] }`.
- Write a test that constructs a signing key, captures the raw bytes address, drops the key, and confirms the bytes at that address are zero (requires `unsafe` and must pin the allocation to prevent moving — treat as a best-effort smoke test, not a hard correctness guarantee).
- Audit all `#[derive(ZeroizeOnDrop)]` structs at review time: every field type must independently implement `ZeroizeOnDrop` or `Zeroize`.

**Warning signs:** `p256` in `Cargo.toml` without explicit `features = ["zeroize"]`; derived `ZeroizeOnDrop` on structs with `SigningKey` fields that haven't been audited.

**Phase mapping:** First commit adding `zeroize`. Check `Cargo.toml` as part of the PR diff.

---

### Pitfall 7: Drop Ordering Exposes Key Material After Dependent State is Cleaned

**What goes wrong:** Rust drops struct fields in declaration order. If a struct holding a `Zeroizing<SigningKey>` also holds an audit log handle or IPC channel that flushes on drop, and the channel drops *after* the key material, the drop of the channel may trigger code that reads (or logs) fields adjacent to where the key was stored. More subtly: if the `SigningKey` is dropped first and the audit log is flushed second, the log flush may read from memory that now contains zeros — benign — but if the audit code accesses the signing key field (e.g., to log the key thumbprint on "agent stopping"), it will read zeroed bytes and emit a corrupt thumbprint, causing confusion.

**Why it happens:** Rust's drop order is deterministic but easy to mis-read when fields are added over time.

**Consequences:** Mostly an operational/correctness issue (corrupt log entries), but in pathological cases could cause a use-after-zeroize audit entry that looks like a security event.

**Prevention:**
- Declare `Zeroizing<>` wrapped key material as the *last* field in any struct, so it drops last (fields drop in reverse declaration order... actually Rust drops fields in *declaration order*, so put key material last to ensure nothing accesses it after zero — verify this for your struct layout).

  **Correction — Rust drop order:** Rust drops struct fields in *forward declaration order* (first field drops first). Therefore, place key material as the *first* field if you want it zeroed before dependent fields run their drop logic, or as the *last* field if you want dependent state (e.g., IPC channel) torn down first. Choose based on what your drop logic needs. Document the chosen order with a comment.

- Write a `Drop` impl for agent state structs that explicitly zeroes key material before flushing final audit events.
- Never access key-bearing fields inside a `Drop` impl for a sibling struct.

**Warning signs:** `AgentState` or similar structs where `signing_key` field position was chosen arbitrarily; `Drop` impls that access multiple fields without considering ordering.

**Phase mapping:** Phase adding `zeroize` + keyring integration, during struct refactoring.

---

### Pitfall 8: YubiKey PIV Exclusive PCSC Lock Conflicts With gpg-agent and Other Applications

**What goes wrong:** The PCSC protocol grants exclusive transactions to one application at a time. `yubikey-agent` (and by extension, any persistent agent holding a `YubiKey` handle open) takes a persistent transaction so it can cache the PIN. This makes the YubiKey's PIV applet inaccessible to every other application — `gpg-agent`, `ykman`, the YubiKey Manager GUI, and any other PCSC client — for as long as the unix-oidc-agent process is running.

On systems where users also use their YubiKey for GPG-signed git commits or PGP email, this will cause silent failures in those workflows whenever the unix-oidc-agent is running in the background.

**Why it happens:** PCSC exclusive transactions are designed for atomic card operations (e.g., PIN verify + sign in one uninterruptible sequence). Holding the transaction open indefinitely is an abuse of the protocol but is done by some agents for PIN caching convenience.

**Consequences:**
- `gpg-agent` returns "Card Error" or "No such device" when unix-oidc-agent holds the lock
- `ykman` fails to connect for firmware queries or key management
- Users experience intermittent "YubiKey not found" errors in unrelated applications

**Prevention:**
- Do not hold an open `YubiKey` handle (and thus PCSC transaction) between signing operations. Open the connection, perform the operation (PIN verify + sign), close the connection. This requires re-entering PIN on each DPoP proof generation unless a separate PIN caching mechanism is implemented.
- For PIN caching without holding the PCSC lock: cache the PIN in a `Zeroizing<String>` in-process (with a configurable TTL), re-open the YubiKey connection each time, and use the cached PIN for the `verify_pin()` call. This is the approach taken by `yubikey-agent` in its non-persistent-transaction mode.
- Document this tradeoff explicitly in the hardware key backend's documentation.

**Warning signs:** `YubiKey::open()` called once at agent startup and the handle stored in agent state without explicit `drop()` between operations.

**Phase mapping:** Hardware key backend phase. Architecture decision before implementation begins.

---

### Pitfall 9: `pcscd` Absent or Stale After System Suspend/Resume

**What goes wrong:** On Linux, `pcscd` (the PC/SC daemon) must be running for any PCSC-based YubiKey access. After system suspend/resume, `pcscd` frequently loses its connection to the USB device and requires a restart. The `yubikey` crate's `open()` call will return a PCSC error (`PcscError::NoReadersAvailable` or similar) until `pcscd` is restarted. Additionally, on RHEL 9, `pcscd` is socket-activated by `systemd` but may not start automatically on first access.

**Why it happens:** USB device reattachment after resume is handled by the kernel, but `pcscd` holds a file descriptor to the CCID driver that becomes stale after resume. The daemon must be signalled or restarted.

**Consequences:** YubiKey signing operations fail non-deterministically on laptop workstations. User sees "hardware key unavailable" with no clear recovery path.

**Prevention:**
1. In the `HardwareSigner` implementation, wrap all `YubiKey::open()` calls in a retry loop (max 3 attempts with 200ms backoff) before returning the error to the caller.
2. Surface the PCSC error code in the error message so users know to run `sudo systemctl restart pcscd`.
3. Implement a health-check command (`unix-oidc-agent hardware-status`) that probes PCSC availability without attempting a sign operation.
4. Ensure PCSC is listed as a runtime dependency in package manifests (`.deb`, `.rpm`).

**Warning signs:** No retry logic around `YubiKey::open()`; error message that says "hardware key unavailable" without actionable guidance.

**Phase mapping:** Hardware key backend phase. Retry logic is a must-have, not a nice-to-have.

---

### Pitfall 10: TPM2 `tss-esapi` Requires `tpm2-abrmd` for Multi-Process Access

**What goes wrong:** Direct TPM access via `/dev/tpm0` grants exclusive access to one process at a time; a second caller receives `EBUSY`. If two processes try to use the TPM concurrently (e.g., the unix-oidc-agent and the system's IMA/measured-boot infrastructure, or a concurrent sudo step-up flow), one will fail. The `tss-esapi` crate supports both direct device TCTI and the `tabrmd` TCTI (access broker/resource manager daemon), but only the `tabrmd` TCTI serialises multi-process access correctly.

**Why it happens:** The TPM hardware itself supports only one command channel. `tpm2-abrmd` is the resource manager that multiplexes access across processes, handling session virtualisation and handle management. Without it, concurrent access is impossible.

**Consequences:** Intermittent TPM signing failures under concurrent load; race condition between agent startup and system TPM consumers.

**Prevention:**
1. Always use `TctiNameConf::Tabrmd` when building with TPM support; fall back to `TctiNameConf::Device` only if `tpm2-abrmd` is explicitly unavailable (and document the single-user-only limitation).
2. Make `tpm2-abrmd` a declared runtime dependency in the `tpm` feature's package manifests.
3. Check for `tpm2-abrmd` presence at startup (probe `org.freedesktop.DBus` for the `com.intel.tss2.Tabrmd` name) and warn if absent.

**Warning signs:** TPM TCTI configured as `Device` without documentation of the concurrency limitation; no check for `tpm2-abrmd` availability.

**Phase mapping:** TPM backend sub-phase of the hardware key phase. Pre-implementation dependency audit.

---

## Moderate Pitfalls

---

### Pitfall 11: YubiKey Firmware Version Differences Break PIV Slot Assumptions

**What goes wrong:** PIV slot availability, key algorithm support, and touch policy support vary across YubiKey firmware versions. YubiKey 4 devices do not support Ed25519; YubiKey 5 firmware < 5.2.3 does not support P-384. Since DPoP requires P-256 (ES256), this is not a blocking issue, but code that attempts to enumerate slots or check firmware capabilities without error handling will panic or return confusing errors on older devices.

**Prevention:** Always check `yubikey.version()` before operations that have firmware version prerequisites. Return a clear error message including the detected firmware version and minimum required version.

**Phase mapping:** Hardware key phase. Add firmware version check to the `YubiKeySigner::new()` constructor.

---

### Pitfall 12: Secure Deletion on CoW Filesystems Requires Explicit Handling

**What goes wrong:** On btrfs (default on openSUSE, Fedora Atomic) and APFS (macOS), `overwrite + unlink` does not guarantee the original data blocks are unrecoverable. CoW filesystems write new data to new blocks; overwriting a file allocates new blocks for the overwritten content while the original blocks remain allocated until the snapshot or reflink reference count reaches zero. Standard `std::fs::remove_file` does not address this.

**Why it happens:** The `FileStorage` migration path (detecting existing file-stored keys and migrating to keyring) must also securely delete the legacy plaintext file. A naive `fs::write(path, zeros); fs::remove_file(path)` does not work on btrfs.

**Consequences:** Forensic recovery of the DPoP private key from btrfs snapshots is possible after "secure" deletion.

**Prevention:**
1. After successfully migrating file-stored keys to the keyring backend, overwrite the file, `fsync()`, unlink, and log a warning that filesystem-level recovery may still be possible on CoW filesystems.
2. Document this limitation in the migration code with a comment referencing the CoW issue.
3. Do not promise "secure deletion" in user-facing messages; use "deleted from the filesystem (CoW filesystems may retain copies in snapshots)".

**Phase mapping:** Keyring activation phase, specifically the file-to-keyring migration path.

---

### Pitfall 13: macOS Keychain Prompts in Non-Interactive Contexts

**What goes wrong:** On macOS, the first time a Keychain item is accessed by a new application binary, the system displays an "Allow" / "Deny" dialog. In automated test environments, CI, or if the binary path changes (e.g., after `cargo build`), this prompt blocks indefinitely. Tests that test the macOS Keychain backend will hang in CI.

**Prevention:**
- The agent binary must be code-signed with a keychain access group entitlement for non-interactive Keychain access in production. This is a build-time step.
- For CI, use `keyring`'s mock backend (opt in via `set_default_credential_builder(mock::default_credential_builder())`); do not test the real Keychain in CI.
- Document the code-signing requirement in the macOS deployment guide.

**Phase mapping:** Keyring activation phase. CI test matrix must explicitly gate real-Keychain tests behind a manual/local flag.

---

### Pitfall 14: YubiKey PIV PIN Retry Counter Exhaustion

**What goes wrong:** PIV slots have a PIN retry counter (default: 3 attempts). If the unix-oidc-agent implements a retry loop for PIN entry (e.g., prompting the user up to 3 times), and a bug causes the loop to re-submit the same wrong PIN, the YubiKey will lock the PIV applet. Recovery requires the PUK (PIN Unblocking Key). If the PUK is also exhausted, the PIV application must be reset, destroying all PIV keys.

**Prevention:**
- Never implement automatic PIN retry. One attempt per user prompt; if wrong, return the error to the user with the remaining retry count.
- Before each PIN submission, call `yubikey.get_pin_retries()` and surface the count to the user ("2 attempts remaining before key lockout").
- Test the retry-counter-exhaustion path with a test YubiKey (not a production device).

**Phase mapping:** Hardware key phase — PIN handling design review before any code is written.

---

## Minor Pitfalls

---

### Pitfall 15: `memsec` vs `libc::mlock` — Transitive Dependency Drag

**What goes wrong:** `memsec` pulls in `winapi` and other platform-specific crates. For the unix-oidc-agent (Linux + macOS only), this adds unnecessary compile-time weight and increases the supply chain surface. `libc::mlock` is available in the already-present `libc` crate with no additional dependency.

**Prevention:** For the agent's narrow use case (locking a fixed-size key buffer), prefer `libc::mlock` directly over adding `memsec`. Only add `memsec` or `secrets` if guard-page protection is required.

**Phase mapping:** `mlock` implementation. Minor dependency audit before adding.

---

### Pitfall 16: Compiler Fence in `zeroize` Does Not Prevent Spectre-Class Leakage

**What goes wrong:** `zeroize` uses `core::sync::atomic::compiler_fence(SeqCst)` and `write_volatile` to prevent the compiler from eliding the zero-write. This is effective against compiler-level dead-store elimination. It does not prevent CPU speculative execution from transiently reading the pre-zero value through a side channel (Spectre variant 1). For the unix-oidc-agent's threat model (same-UID malware, forensic recovery), this is acceptable — Spectre exploitation requires a carefully crafted gadget and is out of scope. Document this explicitly so future contributors do not over-claim the security properties.

**Prevention:** Add a code comment in the key zeroization path: "zeroize prevents compiler dead-store elimination via volatile write + compiler fence. It does not protect against speculative execution side-channels (Spectre). This is acceptable per the agent's threat model."

**Phase mapping:** `zeroize` integration. Comment required, no code change.

---

## Phase-Specific Warnings Summary

| Phase Topic | Likely Pitfall | Mitigation |
|---|---|---|
| Keyring activation as default backend | Silent storage failure on headless Linux (no D-Bus) | Implement backend probe; `keyutils` fallback; log selected backend |
| Keyring activation | Session keyring eviction on logout breaks DPoP key continuity | Use user keyring (`@u`) not session keyring (`@s`) |
| File-to-keyring migration | CoW filesystem (btrfs/APFS) retains plaintext key in snapshots after deletion | Overwrite + fsync + unlink; document limitation |
| `mlock` addition | `ENOMEM` in containers/CI breaks agent startup or silently skips protection | Best-effort `mlock`; log warn on failure; test the failure path |
| `mlock` addition | `Vec<u8>` reallocation moves key bytes to unlocked page | Fix buffer size before locking; prefer `Box<[u8; N]>` |
| `zeroize` integration | Move semantics leave unzeroized stack copies | Pass key bytes by `&mut` reference; keep `SigningKey` on heap in `Arc` |
| `zeroize` integration | `p256` missing `zeroize` feature silently breaks `ZeroizeOnDrop` | Explicit `features = ["zeroize"]` in `Cargo.toml` |
| Hardware key (YubiKey) | Persistent PCSC transaction locks out gpg-agent and ykman | Open/close connection per operation; cache PIN in-process |
| Hardware key (YubiKey) | `pcscd` stale after resume; `systemd` socket activation not triggered | Retry loop in `open()`; surface actionable error message |
| Hardware key (YubiKey) | PIN retry exhaustion locks PIV applet permanently | One attempt per prompt; surface remaining retry count |
| Hardware key (TPM) | Direct `/dev/tpm0` access blocks concurrent processes | Mandate `tpm2-abrmd` TCTI; probe daemon presence at startup |
| macOS CI | Keychain prompt blocks non-interactive test runs | Use mock backend in CI; code-sign binary for production |

---

## Sources

- keyring-rs issue tracker — automatic fallback discussion: https://github.com/hwchen/keyring-rs/issues/133
- keyring-rs issue — headless VM failures: https://github.com/hwchen/keyring-rs/issues/83
- keyring-rs `keyutils` backend (headless recommendation): https://docs.rs/keyring/latest/keyring/keyutils/index.html
- session-keyring(7) Linux man page (PAM revocation behavior): https://www.man7.org/linux/man-pages/man7/session-keyring.7.html
- user-keyring(7) Linux man page: https://man7.org/linux/man-pages/man7/user-keyring.7.html
- Cloudflare — Linux Kernel Key Retention Service: https://blog.cloudflare.com/the-linux-kernel-key-retention-service-and-why-you-should-use-it-in-your-next-application/
- mlock(2) Linux man page (RLIMIT_MEMLOCK, ENOMEM, page alignment): https://man7.org/linux/man-pages/man2/mlock.2.html
- Docker + RLIMIT_MEMLOCK (64 KiB default, containers, IPC_LOCK): https://medium.com/@thejasongerard/resource-limits-mlock-and-containers-oh-my-cca1e5d1f259
- Rust forum — mlock on Vec: https://users.rust-lang.org/t/how-to-mlock-the-memory-allocated-by-a-vec/70344
- zeroize crate docs (volatile write + compiler fence approach): https://docs.rs/zeroize/latest/zeroize/
- Move semantics + zeroize pitfall (stack copies): https://benma.github.io/2020/10/16/rust-zeroize-move.html
- CipherStash — verifying zeroize with assembly: https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd
- Rust internals — move-and-zeroize language limitation: https://internals.rust-lang.org/t/idea-traits-for-zeroizing-before-and-after-move/11728
- yubikey.rs crate docs (PCSC, exclusive access): https://docs.rs/yubikey/latest/yubikey/
- yubikey-agent (persistent transaction / exclusive lock tradeoff): https://github.com/FiloSottile/yubikey-agent
- Yubico — resolving GPG CCID conflicts: https://support.yubico.com/hc/en-us/articles/4819584884124-Resolving-GPG-s-CCID-conflicts
- pcscd must be restarted for ykman access: https://github.com/Yubico/yubikey-manager/issues/548
- tss-esapi Rust docs (TCTI, multi-process, tabrmd): https://docs.rs/tss-esapi/
- tpm2-abrmd (multi-user TPM access broker): https://github.com/tpm2-software/tpm2-abrmd
- Yubico — PIN and touch policies: https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html
- secrets crate (mlock'd SecretVec with guard pages): https://docs.rs/secrets/latest/secrets/struct.SecretVec.html
