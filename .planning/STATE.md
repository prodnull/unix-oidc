# Project State — prmana (née unix-oidc)

**Last updated:** 2026-04-11
**Current milestone:** v1.0.0 Distribution Tier (DT) — external launch readiness

---

## Project Reference

**What this is:** OIDC-native Linux access and privilege control — PAM module
(`pam_prmana.so`) + agent daemon (`prmana-agent`) bringing Device-Auth-Grant OIDC
to SSH and sudo with DPoP proof-of-possession, hardware signers, and SCIM
provisioning. Supporting components: `prmana-scim` (SCIM 2.0 provisioning),
`prmana-kubectl` (exec-credential plugin), `prmana-tools`.

**Core value:** Same IdP policy plane for login and sudo on the long tail of
Linux hosts (dev, CI, edge, GPU) that enterprise gateways don't cover.

**Repository:** `prodnull/unix-oidc` (repo rename deferred — see DT-A decision E)

---

## Current Position

**Phase:** DT-A — Rename + Packages + Repo + kubectl Proof-Point
**Plan:** DT-A-03 (live publish-repo test) — Task 3 of 5
**Status:** ⏸ Blocked (external CI), **unblocked 2026-04-11** after stale-run cleanup

**Progress (DT-A):**

| Plan | Name | Status | Commit |
|---|---|---|---|
| DT-A-01 | Rename unix-oidc → prmana | ✅ done | `89917cc` |
| DT-A-02 | Package toolchain (.deb/.rpm, nfpm) | ✅ done | `3da49ec` |
| DT-A-03 | APT/YUM repo (gh-pages) | ⏳ live test running | Task 2: `7a4b194` |
| DT-A-04 | `prmana-kubectl` exec-plugin + cnf guard | ✅ done | `501c8a1` |
| DT-A-05 | Migration guide + CHANGELOG + README rebrand + fresh-install smoke | ⏳ not started | — |

**Overall DT-A:** 4/5 plans done, 1 in flight.

---

## Active Blockers

1. **Release run 24286961692** (v1.0.0-rc1) — was queued ~1h behind stale CI
   concurrency peg. Unblocked 2026-04-11 ~17:58 UTC by cancelling 6 redundant
   in-progress CI runs on main. Currently running: macOS builds ✅, Linux builds
   and pre-release tests in progress.
2. **Integration Tests (Docker services)** SPIRE + TPM failing — GHCR auth +
   mkdir fixes pushed as `e4c7a8d`, verification pending path-triggered rerun.

---

## Recent Decisions (this session)

- **kubectl tokens HARD-FAIL on `cnf` presence + audience-isolation to PAM
  validator.** Rationale: kubectl cannot send DPoP proofs; `cnf`-bound tokens
  would break k8s auth. Invariant captured in CLAUDE.md.
- **Split `cargo test --all-features` into compile + test + check-all-features.**
  Rationale: 45+ min cold builds; hardware tests ignored anyway.
- **`send_ipc_message` writes JSON+`\n` in one `write_all`.** Rationale: two
  syscalls caused `Broken pipe` race under `--test-threads=4`. Anti-pattern
  captured in `.planning/phases/DT-A-rename-packages-repo-kubectl/.continue-here.md`.
- **GPG signing key: `prodnull@proton.me` UID.** Stored in GH secrets + 1Password,
  published to `keys.openpgp.org`.
- **DT-B split into 4 plans** (postinst wiring, FIPS audit, operator docs, fleet
  runtime tests). Plans drafted but uncommitted at session start.
- **ADR-021 accepted with changes** (2026-04-11, this session): Decision A
  (v1.0 single-process hardening) and Decision B (post-v1.0 helper split) must
  be split. Redlines applied. Implementation tracked as new phase DT-SCIM.

---

## Pending Todos / Handoff Actions

| Action | Context | Blocking? |
|---|---|---|
| Verify release run 24286961692 reaches success | currently in_progress after unblock | no |
| Publish draft release, watch publish-repo.yml | after rc1 success | no |
| Write `docs/crypto-posture.md` | content ready; gated on release green | no |
| Write `.github/workflows/pqc-readiness.yml` | content ready; gated on release green | no |
| DT-A-05 execution | depends on DT-A-03 Task 3 success | no |
| Decide: strip macOS matrix from release.yml? | fallback if runner starvation returns | no |
| Review DT-B-01..04 plans and share with Codex | drafted this session | no |
| YubiKey `test_yubikey_sign_proof` local run | user has YubiKey; CI-ignored | no |

---

## Carried Concerns

- **ADR-021 Decision A is spec, not code.** Zero of the 8 v1.0-blocking controls
  (startup transport policy, request-shaping middleware, audit events, dry_run
  gating, fixed systemd unit) exist in `prmana-scim/` today. New phase DT-SCIM
  created to track implementation.
- **Broken `prmana-scim.service` unit** (`User=prmana` + empty cap set cannot run
  `useradd`; `ExecStart=...serve` references nonexistent subcommand) — known,
  in-flight via DT-SCIM.
- **Concurrency ceiling on CI:** 20 concurrent jobs is GitHub's free-tier cap for
  public repos. Stale in-progress runs can peg it. Watch for recurrence.

---

## Uncommitted Files (session start)

```
 M Cargo.lock
 M deploy/installer/install.sh
 M docs/adr/README.md
 M prmana-agent/src/daemon/socket.rs
 M prmana-agent/src/exchange.rs
 M prmana-agent/src/lib.rs
 M prmana-agent/src/main.rs
 M prmana-kubectl/Cargo.toml
 M prmana-kubectl/src/socket_path.rs
 M prmana-scim/src/auth.rs
 M prmana-scim/src/config.rs
 M prmana-scim/src/main.rs
 M prmana-scim/src/provisioner.rs
 M prmana-scim/src/routes.rs
?? .planning/phases/DT-B-platform-hardening/DT-B-0{1,2,3,4}-PLAN.md
?? prmana-agent/src/url_policy.rs
?? scripts/prmana_sync.sh
```

---

## Session Continuity

- **Last session:** 2026-04-11 (overnight CI fix loop + ADR-021 review)
- **Stopped at:** Release run blocked on GHA runner congestion; post-unblock
  follow-ups queued.
- **Resume files:**
  - `.planning/HANDOFF.json` (structured handoff from pause, pre-unblock)
  - `.planning/phases/DT-A-rename-packages-repo-kubectl/.continue-here.md`
    (DT-A-03 checkpoint + critical anti-patterns)
- **Latest commit (main):** `6732ba0` (wip DT-A-03 pause note) — release tag
  `v1.0.0-rc1` points at `047532d`.

---

## Artifact Map

| Milestone | Artifact | Path |
|---|---|---|
| DT (v1.0) | Phase context | `.planning/phases/DT-A-*/DT-A-CONTEXT.md` |
| DT (v1.0) | DT-A plans | `.planning/phases/DT-A-*/DT-A-0{1..5}-PLAN.md` |
| DT (v1.0) | DT-B plans | `.planning/phases/DT-B-*/DT-B-0{1..4}-PLAN.md` (uncommitted) |
| DT (v1.0) | DT-SCIM plans | `.planning/phases/DT-SCIM-*/` (new this session) |
| DT (v1.0) | Roadmap | `.planning/ROADMAP.md` (repopulated this session) |
| v2.2 | Historical summary | `.planning/MILESTONES.md` |
| ADRs | ADR-019 SCIM provisioning | `docs/adr/019-scim-provisioning.md` |
| ADRs | ADR-021 SCIM hardening | `docs/adr/021-scim-service-hardening-and-privilege-separation.md` |
