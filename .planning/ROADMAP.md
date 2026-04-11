---
milestone: v1.0.0
milestone_name: Distribution Tier — External Launch Readiness
status: active
last_updated: 2026-04-11
---

# Distribution Tier (DT) Roadmap — v1.0.0

This roadmap covers the work required to ship prmana `v1.0.0` as an externally
consumable product: renamed crate/binaries, signed packages, public APT/YUM
repo, fleet-verified MAC policies, SCIM hardening, and the kubectl exec-plugin
proof-point.

**Starting state:** prmana is functionally complete at the v3.x internal
milestone (multi-IdP failover, Token Exchange, SCIM provisioning, hardware
signers, audit chain). It is not externally deployable: no packages, no repo,
broken SCIM systemd unit, unhardened SCIM service, no signed distribution.

**Shipping goal:** `v1.0.0` GA with a signed .deb/.rpm on a public repo, a
runnable SCIM provisioning service, and documented operator workflows across
the Linux support matrix.

---

## Phase Map

| Phase | Name | Status | Depends on | Wave |
|---|---|---|---|---|
| [DT-0](phases/DT-0-deployment-test-harness/) | Deployment test harness (Terraform fleet) | ✅ Complete | — | 0 |
| [DT-A](phases/DT-A-rename-packages-repo-kubectl/) | Rename + Packages + Repo + kubectl Proof-Point | ⏳ In progress (4/5 plans done) | DT-0 | 1 |
| [DT-B](phases/DT-B-platform-hardening/) | Platform Hardening (SELinux/AppArmor/FIPS/fleet) | 📝 Plans drafted | DT-A-03 | 2 |
| [DT-SCIM](phases/DT-SCIM-v1-hardening/) | SCIM Decision A Hardening (ADR-021) | 🆕 Spec'd, not planned | — (parallel to DT-B) | 2 |
| [DT-C](phases/DT-C-documentation/) | Operator docs + migration guide | 🔮 Future | DT-A, DT-B, DT-SCIM | 3 |
| [DT-D](phases/DT-D-release-validation/) | Release validation across support matrix | 🔮 Future | DT-B, DT-SCIM | 4 |
| DT-E | Post-v1.0 work (kubectl mTLS, SCIM helper split, SRE step-up) | 🔮 Out of scope for v1.0 | v1.0 GA | — |

**Wave semantics:**
- Wave 0: prerequisites (test harness)
- Wave 1: renaming and packaging (sequential — DT-A must finish first)
- Wave 2: hardening work — DT-B (MAC policy) and DT-SCIM (perimeter controls)
  run in parallel; neither depends on the other
- Wave 3: operator-facing documentation
- Wave 4: final support-matrix validation before GA tag

---

## Phase DT-A: Rename + Packages + Repo + kubectl Proof-Point

**Status:** ⏳ 4/5 plans complete, DT-A-03 (live publish-repo test) in flight.

| Plan | Name | Status | Commit |
|---|---|---|---|
| DT-A-01 | Rename unix-oidc → prmana | ✅ | `89917cc` |
| DT-A-02 | Package toolchain (nfpm .deb/.rpm) | ✅ | `3da49ec` |
| DT-A-03 | Live publish-repo test (v1.0.0-rc1 on gh-pages) | ⏳ | Task 2 `7a4b194`, Task 3 CI running |
| DT-A-04 | prmana-kubectl exec-plugin + cnf guard | ✅ | `501c8a1` |
| DT-A-05 | Migration guide + CHANGELOG + README rebrand + fresh-install smoke | ⏸ | — |

**Exit criteria:** `apt install prmana` on Debian 12 and `dnf install prmana`
on Rocky 9 both succeed and yield a runnable service, verified by DT-A-03 live
test against gh-pages.

---

## Phase DT-B: Platform Hardening

**Status:** 📝 Plans DT-B-01..04 drafted, uncommitted. Awaits DT-A-03 complete.

| Plan | Name | Wave | Depends on |
|---|---|---|---|
| DT-B-01 | postinst MAC policy wiring + nfpm manifests + systemd hardening score | 1 | — |
| DT-B-02 | FIPS posture documentation (mode vs 140-3) | 1 | — |
| DT-B-03 | SELinux/AppArmor operator guides | 2 | DT-B-01 |
| DT-B-04 | Fleet runtime tests (Rocky 9 + AL2023 + Debian 12 + Ubuntu 22.04 + fips=1) | 3 | DT-B-01, 02, 03 |

**Exit criteria:** Zero AVC / AppArmor denials across support matrix on fresh
install → SSH auth → sudo step-up cycle. Rocky 9 + `fips=1` confirmed working.

---

## Phase DT-SCIM: SCIM Decision A Hardening

**Status:** 🆕 ADR-021 Decision A accepted 2026-04-11. Phase spec'd, no plans
written yet. Implementation scope derived directly from ADR-021 §A1–A6.

**Why this is a separate phase and not part of DT-B:**
- DT-B covers MAC policy / SELinux / AppArmor / FIPS — kernel- and
  distro-level defenses. Decision A covers application-level perimeter
  controls for the SCIM HTTP listener. The work is disjoint.
- Decision A is ADR-021-level and has its own acceptance criteria.
- Running DT-B and DT-SCIM in parallel cuts the critical path to v1.0 tag.

**Scope (from ADR-021 §A1–A6):**

| Plan (planned) | Name | ADR ref | Status |
|---|---|---|---|
| DT-SCIM-01 | Fix systemd unit + CLI `serve` subcommand + config surface (TLS, proxy CIDRs, rate-limit knobs, audit fields) | Context + §A1 | not started |
| DT-SCIM-02 | Startup-enforced transport policy (bind-target matrix + rustls TLS 1.3 + fail-closed on missing key material) | §A1 | not started |
| DT-SCIM-03 | Trusted proxy model (direct peer CIDR match + strip-and-audit for untrusted forwarded headers + single-hop limitation) | §A2 | not started |
| DT-SCIM-04 | Request-shaping middleware (rate-limit library choice + composite key extractor + body/header/timeout/concurrency + slowloris read-idle + discovery endpoint carveout) | §A3 | not started |
| DT-SCIM-05 | Structured audit events joining ADR-010 HMAC chain + rejection event types + `jwt_jti` in `BearerClaims` | §A4 | not started |
| DT-SCIM-06 | Remove `dry_run` from `ScimConfig`, migrate tests to `FakeAccountBackend` via `with_account_backend` | §A5 | not started |
| DT-SCIM-07 | Failure-behavior contract: 500 for synchronous operational failures, 503+Retry-After reserved for concurrency + helper paths | §A6 | not started |

**NOT in scope (Decision B — post-v1.0):**
- Helper binary (`prmana-scim-helper`) + Unix socket IPC + `SO_PEERCRED` peer auth
- Front-end UID split (`prmana-scim` service account distinct from agent UID)
- Helper RPC protocol (`AF_UNIX` stream + length-prefixed JSON + versioning)
- socket-activated systemd units for front-end + helper
- `PrivateUsers=` enablement on support matrix

**Exit criteria:**

1. `prmana-scim.service` loads cleanly on `systemctl start` with the
   privileges required to run `useradd`.
2. `curl -s https://scim.example.com/ServiceProviderConfig` over native TLS
   succeeds; plain HTTP on the same listener refused at startup.
3. An Okta bulk-provisioning burst (1000 POSTs over 30s) hits rate limits
   deterministically with SCIM-shaped 429 responses and `Retry-After`
   headers, without pegging concurrency or causing memory growth.
4. All rejected requests (429/413/431/503-concurrency/timeout) emit audit
   events to the ADR-010 HMAC chain with distinct `result` values.
5. Grep audit for `"dry_run"` in `prmana-scim/src/` returns zero matches
   outside `#[cfg(test)]`.
6. `systemd-analyze security prmana-scim.service` hardening score is reported
   and does not regress relative to baseline.
7. An ADR-021 Decision A waiver table (if any) is explicit in the v1.0
   release notes — ideally empty.

**Dependencies:** None (parallel with DT-B). Touches only `prmana-scim/` and
`contrib/systemd/prmana-scim.service`.

**Assumed non-dependencies:** DT-A rename work is already applied to the SCIM
crate (verified this session — `prmana-scim` is the crate name).

---

## Phase DT-C: Operator Documentation

**Status:** 🔮 Future. Depends on DT-A, DT-B, DT-SCIM.

Scope: `docs/operations/`, `docs/migration/unix-oidc-to-prmana.md`, break-glass
runbook, SIEM integration guide, rollback procedure. Content has partial
drafts from prior sessions; DT-C consolidates and ships them.

---

## Phase DT-D: Release Validation

**Status:** 🔮 Future. Depends on DT-B, DT-SCIM.

Scope: full support-matrix dry-run on the DT-0 fleet (Ubuntu 22.04/24.04,
Debian 12, Rocky 9, AL2023) → signoff → `v1.0.0` tag.

---

## Deferred to Post-v1.0 (DT-E or later)

- ADR-021 Decision B (SCIM helper split + `SO_PEERCRED` + RPC versioning)
- kubectl ephemeral mTLS certs (ADR pending; replaces bearer-token exec cred)
- SRE step-up flow (CIBA from kubectl)
- Admission webhook
- Ubuntu 24.04 SPIRE/SPIFFE integration validation

---

## Cross-Phase Invariants

These must hold throughout the milestone and are checked at release-validation
time by DT-D:

- No commit to `main` regresses CI to red — every push goes through
  Integration Tests (Docker), CI, and Security Scanning as of `d596e69`.
- `v1.0.0-rcN` tag points at a commit that passed the full matrix.
- GPG signing key identity: `prodnull@proton.me` via `keys.openpgp.org`.
- Release artifacts carry SLSA provenance produced in per-target build jobs
  (Codex review decision from DT-A-02).
- `PRMANA_TEST_MODE` / `test-mode` feature flag is verified absent from all
  release binaries (CLAUDE.md invariant).
- `cnf` claim never populated in kubectl-issued tokens (CLAUDE.md invariant).
- SCIM audit stream joins the ADR-010 HMAC chain (ADR-021 §A4).
- Marketing and SECURITY.md do not describe SCIM as "privilege-separated"
  until Decision B ships (ADR-021 §Effect on ADR-019).
