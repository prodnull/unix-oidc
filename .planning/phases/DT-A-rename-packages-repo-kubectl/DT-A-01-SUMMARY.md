---
plan: DT-A-01
phase: DT-A-rename-packages-repo-kubectl
status: completed
completed_at: 2026-04-11
tasks_completed: 3
tasks_total: 3
---

# DT-A-01 Summary: Hard-cut rename unix-oidc → prmana

## What Was Built

Complete mechanical rename of the entire workspace from `unix-oidc` / `UNIX_OIDC` to
`prmana` / `PRMANA`. 329 files changed (4250 insertions, 3849 deletions), preserving full
git history via `git mv` for all three main crate directories.

## Key Files Created / Modified

- **`pam-prmana/`** — renamed from `pam-unix-oidc/`; PAM module now produces `libpam_prmana.so`
- **`prmana-agent/`** — renamed from `unix-oidc-agent/`; binary `prmana-agent`
- **`prmana-scim/`** — renamed from `unix-oidc-scim/`; binary `prmana-scim`
- **`prmana-agent/src/storage/migration.rs`** (new) — keyring key-name migration module
- **`contrib/systemd/prmana-agent.service`** — renamed + hardened (replaces unix-oidc-agent.service)
- **`contrib/systemd/prmana-agent.socket`** — renamed
- **`contrib/systemd/prmana.tmpfiles.conf`** — renamed
- **`test/fixtures/env/prmana.env`** — renamed from unix-oidc.env
- **`test/fixtures/keycloak/prmana-realm.json`** — renamed Keycloak realm
- **`CLAUDE.md`** — storage invariant #11 added (legacy key migration)

## Verification Results

| Check | Result |
|-------|--------|
| `cargo check --workspace` | ✅ 22 crates, clean |
| Migration unit tests (`storage::migration`) | ✅ 6/6 passed |
| Residual reference audit | ✅ 4 expected hits only (migration.rs doc comments + CLAUDE.md invariant) |
| Git history preserved | ✅ `git mv` used for all directory renames |

### Residual Audit Detail

The 4 grep hits are documentation only (not code):
1. `prmana-agent/src/storage/migration.rs:1` — module doc comment
2. `prmana-agent/src/storage/migration.rs:20` — comment explaining LEGACY_KEY allowlist
3. `prmana-agent/src/storage/migration.rs:58` — function doc comment
4. `CLAUDE.md:274` — storage invariant #11 documenting what migration reads

All are in the migration module or its documentation. Zero dangling code references.

## Security Properties

- **T-DTA01-01 (Info Disclosure)**: Migration logs key NAMES only; no credential values
  logged. Unit test 6 verifies no credential appears in captured logs.
- **T-DTA01-02 (Tampering)**: Write-before-delete atomicity — if new-name write fails,
  legacy key is NOT deleted. Unit test 4 covers this path.
- **T-DTA01-03 (DoS)**: Migration failure is non-fatal WARN; daemon continues with
  current-name keys.
- **T-DTA01-05 (EoP)**: `PRMANA_TEST_MODE` sentinel in release.yml CI updated (was
  `UNIX_OIDC_TEST_MODE`). Release pipeline test-mode gate is correct.
- **T-DTA01-06 (Info)**: `libpam_prmana.so` is clean — LEGACY_KEY_* constants live in
  `prmana-agent`, not in the PAM module.

## Deviations

- Tasks 1 and 2 committed atomically (single commit) because `pub mod migration;` in
  `storage/mod.rs` creates a compile dependency between the rename and the new module.
  Splitting would have produced a non-compiling intermediate state.
- CHANGELOG.md: historical entries preserved verbatim. New top entry updated to prmana.
- GitHub repo URL (`prodnull/unix-oidc`) left unchanged per CONTEXT.md decision E.
- Cosign `--certificate-identity-regexp` left unchanged (points to old GitHub URL).
- `OIDC_ISSUER` and `OIDC_CLIENT_ID` env vars left unchanged (user-supplied IdP config).

## Self-Check

- [x] All three crate directories renamed via `git mv` (history preserved)
- [x] All `Cargo.toml` package names, binary names, and path deps updated
- [x] `Cargo.lock` regenerated
- [x] All Rust source `use pam_unix_oidc::` paths updated to `use pam_prmana::`
- [x] UNIX_OIDC_ env var prefix → PRMANA_ throughout source and CI
- [x] systemd units, socket, tmpfiles renamed and content updated
- [x] CI workflows, Dockerfiles, docker-compose files updated
- [x] Keycloak realm unix-oidc-test → prmana-test
- [x] Deploy scripts, Ansible roles, templates updated
- [x] Keyring migration module created with 6 unit tests
- [x] StorageRouter calls migrate_legacy_key_names() at startup
- [x] CLAUDE.md storage invariant #11 added
- [x] `cargo check --workspace` passes
- [x] Migration tests pass (6/6)
- [x] Residual audit: zero dangerous hits
