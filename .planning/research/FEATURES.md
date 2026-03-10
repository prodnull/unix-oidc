# Feature Landscape: Client-Side Key Protection for OIDC/SSH Agents

**Domain:** Credential management daemon / OIDC SSH agent with DPoP key protection
**Researched:** 2026-03-10
**Overall confidence:** HIGH (codebase direct inspection + MEDIUM for competitor internals)

---

## Framing: What Makes This Agent Different

Standard ssh-agent, gpg-agent, and even 1Password SSH agent are general-purpose key managers. This
agent is purpose-built for a single operation: holding DPoP private keys and OAuth tokens so that
the PAM module can present cryptographically bound proofs. That narrows the feature surface
considerably, but raises the security bar: **a stolen DPoP private key defeats the entire
proof-of-possession model.** Every feature decision flows from that threat.

The agent currently has: software signing via `SoftwareSigner`, two storage backends (`FileStorage`
active, `KeyringStorage` dormant), an IPC socket, structured audit logging, and a trait-based
abstraction for both signing (`DPoPSigner`) and storage (`SecureStorage`). The active `FileStorage`
implementation writes key bytes plaintext to 0600 files on CoW-capable filesystems without
zeroization on drop or delete.

---

## Competitive Reference: What Each Agent Does

### OpenSSH ssh-agent
- In-memory only; no at-rest persistence (keys must be re-added after restart)
- Since 2019: "shielded private key" — encrypts in-memory key bytes with a 16 KB symmetric pre_key,
  protects against Spectre/Meltdown read primitives [HIGH confidence, OpenSSH source]
- No mlock by default on all platforms; key lifetime TTL via `ssh-add -t`
- No hardware-aware deletion; no CoW awareness
- Per-use confirmation flag (`-c` in ssh-add) calls a confirmation program before each signing op
- Forwarding is a footgun (root on intermediary sees agent socket); ProxyJump is the modern answer

### gpg-agent
- At-rest: passphrase-encrypted key files under `~/.gnupg/private-keys-v1.d/` (one file per key)
- In-memory: libgcrypt's "secure memory" region (`mlock`-ed pool), configurable size
- Passphrase cache with configurable TTL (default 600 s, max-cache-ttl ceiling)
- Pinentry integration for interactive passphrase/PIN entry with optional keyboard grab (anti-X-sniff)
- SSH key confirmation flag via `sshcontrol`
- Hardware: smartcard support via `scdaemon`, handles YubiKey OpenPGP applet

### Teleport `tsh`
- Default: stores user key + short-lived certificates on filesystem (plaintext, protected by path)
- Hardware mode: YubiKey PIV (series 5+); key generated on-device and non-exportable
- PIN policy and touch policy enforced per-role or cluster-wide
- PIN caching: cached internally by YubiKey hardware for seconds; Teleport Connect acts as hardware
  key agent to cache PIN across `tsh`/`tctl` invocations
- Migration: no automated path from software to hardware; hardware login replaces software login
- Key lifetime: certificates are inherently short-lived (1h–12h); no separate TTL needed
  [MEDIUM confidence — docs reviewed via search; internal implementation not inspected]

### Smallstep `step-ssh`
- Short-lived certificates as the primary key-protection strategy: stolen cert expires quickly
- CA key protection: PKCS#11 HSM, AWS/GCP/Azure KMS, YubiKey PIV (CA side, not client side)
- Client-side: no special key hardening documented; relies on short cert TTL as the threat model
- Key protection levels vary by tier (open-source vs managed)
  [MEDIUM confidence — official docs reviewed via search]

### 1Password SSH agent
- Keys never leave the 1Password encrypted vault; private key material never touches local disk
  in raw form [HIGH confidence — official security page]
- Authorization model: per-process, per-key approval prompts; uses Touch ID / Windows Hello /
  Apple Watch / account password
- No hardware key support beyond biometric unlock of the vault itself
- No key TTL; vault lock controls access window
- Process isolation: signing happens inside 1Password process; agent socket is just a proxy
  [HIGH confidence — official developer docs]

### Secretive (macOS)
- Keys generated inside Secure Enclave: non-exportable by hardware design
- Touch ID / Apple Watch required per-use (configurable, "cached" touch policy = 15 s window)
- Notification on every key access (audit trail in UX)
- 2025 (macOS Tahoe): post-quantum MLDSA-65/MLDSA-87 key support; out-of-process request parsing
- Hard limitation: Secure Enclave-bound keys cannot be backed up or migrated to new hardware
- Linux/headless: not applicable — macOS-only product
  [HIGH confidence — official docs + GitHub README]

### yubikey-agent (FiloSottile)
- Minimal design: PIN every session, touch every login — no shortcuts
- Management key randomized and stored in PIN-protected YubiKey metadata
- Touch policy: "always" by default; "cached" (15 s) available but discouraged
- Pure Go, no daemon restart required (persistent PIV transaction)
- No software fallback; if YubiKey is absent, agent is inoperative

---

## Table Stakes

Features users expect. Missing = product feels incomplete or security-broken.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **OS keyring as default storage** | File-based storage of raw key bytes is demonstrably inadequate; every comparable agent stores at-rest secrets in OS-managed protected storage | Low | `KeyringStorage` exists, needs wiring as default; `FileStorage` becomes headless fallback |
| **Zeroization on key drop** | Key bytes in heap are readable until GC; `ssh-agent` shielding and gpg-agent secure memory both address this; absence is a regression vs. peers | Low | `zeroize` crate from RustCrypto, derive macro on `SoftwareSigner.signing_key`; `SigningKey` in `p256` already implements `ZeroizeOnDrop` |
| **mlock / memory pinning** | Without `mlock`, key pages may be written to swap, crash dumps, or hibernation files — all accessible to offline attackers; gpg-agent uses libgcrypt secure pool | Medium | `libc::mlock` directly, or `memsec` crate; must handle `RLIMIT_MEMLOCK` gracefully with fallback + warning |
| **Secure credential deletion** | `FileStorage::delete()` currently zero-fills then removes — correct intent but incomplete on CoW filesystems (APFS, btrfs with snapshots) | Medium | For file backend: overwrite + unlink is best achievable effort; document CoW limitation explicitly. For keyring backend: OS handles secure erasure. For memory: zeroize before dealloc |
| **Graceful fallback chain** | Headless servers lack D-Bus or Keychain; agent must not fail hard if keyring unavailable | Low | Try keyring → log warning → fall back to file store; configuration override to force one or the other |
| **Migration: file → keyring** | Existing deployments have key material in `~/.local/share/unix-oidc-agent/`; silent breakage on upgrade is unacceptable | Medium | On startup: detect existing file-stored keys, offer/perform migration to keyring, wipe file securely on success |
| **Key TTL / lifetime limit** | Every comparable agent (ssh-agent `-t`, gpg-agent `default-cache-ttl`, Teleport short-lived certs) limits credential exposure window | Low-Medium | Configurable per-policy; auto-logout/key-unload on expiry; important for step-up sudo sessions |
| **Per-use confirmation** (headless-optional) | ssh-agent `-c`, Secretive notifications, 1Password approval prompts all give user visibility into when keys are used | Low | PAM invocations are daemon-driven; a syslog audit event per signing operation satisfies the headless case |
| **Structured audit log for every signing op** | PAM auth systems require non-repudiation; existing logging infra present, needs per-proof log entries | Low | Already partially exists; ensure DPoP proof generation events carry: timestamp, target, method, thumbprint |

---

## Differentiators

Features that set this agent apart. Not expected by the market, but competitively valuable.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Hardware key backend: YubiKey PIV** | Only agent in this space combining OIDC + DPoP + hardware non-exportable key — Teleport requires its own CA; 1Password uses vault; nobody binds OIDC DPoP keys to PIV slots | High | `DPoPSigner` trait already designed for this. Uses `yubikey` crate (optional cargo feature). Key ops: `PIV slot 9a`, ES256, touch policy configurable. PIN caching via agent |
| **Hardware key backend: TPM 2.0** | Linux-native hardware binding without YubiKey dependency; `tss-esapi` crate; key sealed to TPM — survives reboot, non-exportable | High | Optional feature. TPM2 PKCS#11 via `tpm2-pkcs11` is the Linux standard path, or direct `tss-esapi`. Not every TPM supports P-256 ECDSA — must verify at provisioning time |
| **Filesystem-aware deletion UX** | Explicitly document and warn when running on CoW filesystem (APFS, btrfs); recommend encryption-at-rest layer (FileVault, LUKS) as the correct mitigant — honest and useful | Low | Detect via `statfs`/`statvfs` filesystem type code at startup; log advisory if CoW detected and file backend in use |
| **Automatic hardware-to-software fallback detection** | If YubiKey is removed mid-session, agent detects and either pauses signing until hardware returns or falls back gracefully (configurable) | Medium | Poll PIV state on signing failure; expose "hardware required" policy flag |
| **Token-bound key rotation** | When a new OAuth token is issued (refresh cycle), rotate the DPoP key pair atomically — old key zeroized, new key bound to new token cnf thumbprint | Medium | Ensures forward secrecy within a session window; no other compared agent does this |
| **PKCS#11 signer backend** | General escape hatch for any PKCS#11 device (HSM, smart card, cloud KMS via pkcs11-provider); makes `DPoPSigner` implementable without bespoke device crates | High | Requires `pkcs11` or `cryptoki` crate; satisfies enterprise HSM requirements without per-device code |

---

## Anti-Features

Features to explicitly NOT build in this milestone.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Custom memory encryption (OpenSSH-style "shielding")** | OpenSSH shielding re-encrypts key in memory with a separate AES key — complex, brittle, partially defeated by same-UID attacker. The `p256::SigningKey` already implements `ZeroizeOnDrop`; mlock is the correct mechanism at this level | Use `zeroize` + `mlock` — simpler, correct, audited |
| **Key export / backup of hardware keys** | Secretive explicitly refuses this; yubikey-agent refuses it; the entire security value of hardware keys is non-exportability. Implementing "backup" of HSM-bound keys undermines the threat model | Document limitation clearly; recommend users provision multiple hardware tokens for redundancy |
| **Agent forwarding / socket sharing** | OpenSSH agent forwarding is a well-documented footgun (root on intermediate host owns the socket). This agent's socket is PAM-IPC, not general-purpose | Keep IPC socket non-forwardable, document this explicitly |
| **Interactive PIN prompt in PAM path** | PAM modules cannot block on user input in SSH keyboard-interactive flows reliably; gpg-agent's pinentry model does not translate to daemon PAM invocation | PIN/biometric is a login-time or agent-unlock-time operation, not per-PAM-call |
| **Token decryption / JOSE handling** | The agent's job is DPoP signing and token storage. Parsing/decrypting tokens beyond what's needed for expiry checking adds attack surface | Keep token handling in PAM module where validation occurs |
| **Agent forwarding over SSH** | Same footgun as above; adds IPC complexity and socket exposure on remote hosts | ProxyJump is the answer for multi-hop; token exchange (ADR-005) for server-to-server delegation |
| **Networked credential sync** | 1Password-style vault sync requires a server-side component, key wrapping protocols, and account management. Out of scope | Users synchronize via their IdP credential; DPoP key is per-device by design (proof of possession requires the private key to stay on one device) |
| **GUI / tray icon** | Secretive and 1Password are GUI-native desktop tools. This agent targets Linux servers and developer workstations where headless is the primary deployment | CLI and daemon; use syslog/journald for operational visibility |

---

## Feature Dependencies

```
mlock (memory pinning)
  └── zeroize (memory zeroing on drop)  [zeroize must happen before mlock'd region is munlock'd]

OS keyring as default
  └── migration: file → keyring  [must migrate before old file-based key expires or agent restarts]
  └── graceful fallback chain    [keyring probe must precede fallback decision]

hardware key backend: YubiKey
  └── DPoPSigner trait (already exists)
  └── yubikey optional feature flag
  └── PIN caching strategy  [must design before implementing to avoid usability pitfalls]
  └── hardware-to-software fallback detection

hardware key backend: TPM
  └── DPoPSigner trait (already exists)
  └── tss-esapi optional feature flag
  └── P-256 capability probe at provisioning time

PKCS#11 signer
  └── DPoPSigner trait (already exists)
  └── Supersedes YubiKey + TPM backends if general enough (evaluate tradeoff)

key TTL / lifetime
  └── OS keyring as default  [keyring delete must succeed for TTL expiry to work cleanly]
  └── zeroize  [key must be zeroed on TTL expiry, not just dropped]

per-use audit log
  └── existing tracing/syslog infra (already exists)

filesystem CoW detection + warning
  └── file backend (already exists)

token-bound key rotation
  └── OS keyring as default
  └── zeroize
  └── existing token refresh logic
```

---

## MVP Recommendation for This Milestone

This is a hardening milestone on an existing, working agent. The MVP for this milestone is the
minimum set of changes that closes the primary threat model gap — plaintext key bytes on disk —
without requiring new cargo features or hardware.

**Prioritize (Phase 1 — closes the primary threat gap):**
1. `zeroize` on `SoftwareSigner` (derives `ZeroizeOnDrop`; `p256::SigningKey` supports it)
2. `mlock` of key buffer on load from any storage backend (with RLIMIT_MEMLOCK fallback/warning)
3. OS keyring wired as default; `FileStorage` becomes explicit fallback
4. Secure deletion: zeroize in-memory buffer before dealloc; document CoW limitation for file backend
5. Migration: detect existing file-stored keys at startup, migrate to keyring, wipe file

**Phase 2 — key lifecycle hardening:**
6. Key TTL: configurable lifetime with auto-zeroize on expiry
7. Filesystem CoW detection and advisory warning
8. Per-signing-op audit log events (structured, carries thumbprint + target)

**Defer to future milestones:**
- YubiKey PIV backend (optional feature; high complexity; design separately)
- TPM 2.0 backend (optional feature; device-specific; design separately)
- PKCS#11 general backend (evaluate whether it supersedes YubiKey/TPM backends first)
- Token-bound key rotation (requires token refresh redesign)

---

## Sources

- OpenSSH shielded private key: https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/ [MEDIUM — third-party analysis of OpenSSH source]
- 1Password SSH agent security model: https://developer.1password.com/docs/ssh/agent/security/ [HIGH — official docs]
- Secretive features and 2025 updates: https://secretive.dev/ and https://github.com/maxgoedjen/secretive [HIGH — official project]
- Teleport hardware key support: https://goteleport.com/docs/zero-trust-access/authentication/hardware-key-support/ [HIGH — official docs]
- yubikey-agent design: https://github.com/FiloSottile/yubikey-agent [HIGH — official project]
- Smallstep cryptographic protection: https://smallstep.com/docs/step-ca/cryptographic-protection/ [HIGH — official docs]
- TPM2 PKCS#11: https://github.com/tpm2-software/tpm2-pkcs11 [HIGH — official project]
- zeroize crate: https://docs.rs/zeroize/latest/zeroize/ [HIGH — official crate docs]
- memsecurity crate: https://docs.rs/memsecurity [HIGH — official crate docs]
- CoW filesystem deletion behavior: multiple Linux kernel mailing list threads [MEDIUM]
- gpg-agent secure memory and pinentry: https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html [HIGH — official docs]
- Teleport hardware key PIN caching: https://github.com/gravitational/teleport/pull/54297 [HIGH — official PR]
- ssh-agent key lifetime best practices: https://goteleport.com/blog/how-to-use-ssh-agent-safely/ [MEDIUM — vendor blog, technically accurate]
