---
phase: 8
slug: username-mapping-group-policy-break-glass
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test (`cargo test`) |
| **Config file** | none — `#[cfg(test)]` modules inline in each source file |
| **Quick run command** | `cargo test -p pam-unix-oidc 2>&1 \| tail -5` |
| **Full suite command** | `cargo test -p pam-unix-oidc` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc 2>&1 | tail -5`
- **After every plan wave:** Run `cargo test -p pam-unix-oidc`
- **Before `/gsd:verify-work`:** Full suite must be green + `cargo clippy -p pam-unix-oidc -- -D warnings` + `cargo fmt --check -p pam-unix-oidc`
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 08-01-01 | 01 | 0 | IDN-01 | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_claim_extraction` | ❌ W0 | ⬜ pending |
| 08-01-02 | 01 | 0 | IDN-02 | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_strip_domain` | ❌ W0 | ⬜ pending |
| 08-01-03 | 01 | 0 | IDN-02 | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_regex_named_group` | ❌ W0 | ⬜ pending |
| 08-01-04 | 01 | 0 | IDN-02 | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_pipeline_chain` | ❌ W0 | ⬜ pending |
| 08-01-05 | 01 | 0 | IDN-03 | unit | `cargo test -p pam-unix-oidc identity::collision::tests::test_single_domain_ok` | ❌ W0 | ⬜ pending |
| 08-02-01 | 02 | 0 | IDN-04 | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_group_member_allowed` | ❌ W0 | ⬜ pending |
| 08-02-02 | 02 | 0 | IDN-04 | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_group_member_denied` | ❌ W0 | ⬜ pending |
| 08-02-03 | 02 | 0 | IDN-05 | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_sudo_group_allowed` | ❌ W0 | ⬜ pending |
| 08-03-01 | 03 | 0 | IDN-06 | unit | `cargo test -p pam-unix-oidc tests::test_break_glass_returns_ignore` | ❌ W0 | ⬜ pending |
| 08-03-02 | 03 | 0 | IDN-07 | unit | `cargo test -p pam-unix-oidc audit::tests::test_break_glass_event_serialization` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/src/identity/mod.rs` — new module with re-exports
- [ ] `pam-unix-oidc/src/identity/mapper.rs` — UsernameMapper, transforms, tests
- [ ] `pam-unix-oidc/src/identity/collision.rs` — static injectivity analysis, tests
- [ ] `pam-unix-oidc/src/sssd/groups.rs` — resolve_nss_group_names, is_group_member, tests
- [ ] `regex = "1.10"` added to `pam-unix-oidc/Cargo.toml`
- [ ] `groups_enforcement: EnforcementMode` added to `SecurityModes`
- [ ] `login_groups: Vec<String>` added to `SshConfig`
- [ ] `sudo_groups: Vec<String>` added to `SudoConfig`
- [ ] `accounts: Vec<String>` in `BreakGlassConfig`
- [ ] `identity: IdentityConfig` added to `PolicyConfig`
- [ ] `AuditEvent::BreakGlassAuth` variant + constructor
- [ ] `AuditEvent::event_type()` match arm for `BreakGlassAuth`

*All are new additions — no existing test infrastructure needs replacement.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Break-glass via actual SSH | IDN-06 | Requires PAM stack + sshd | Configure break-glass user, SSH in, verify PAM_IGNORE delegates to pam_unix |
| SSSD group resolution with real IdP | IDN-04 | Requires FreeIPA/LDAP + SSSD | Join domain, verify groups resolves via `id username`, test login |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
