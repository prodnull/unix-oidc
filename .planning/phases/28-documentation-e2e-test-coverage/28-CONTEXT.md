# Phase 28: Documentation + E2E Test Coverage - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Three documentation deliverables (standards compliance matrix update, identity rationalization guide, JTI cache architecture doc) plus five E2E test suites that automate human-verification gaps from prior phases. Eight requirements: DOC-01, DOC-02, DOC-03, E2ET-01, E2ET-02, E2ET-03, E2ET-04, E2ET-05.

</domain>

<decisions>
## Implementation Decisions

### Standards Compliance Matrix (DOC-01)
- **Update existing doc, not create from scratch.** `docs/standards-compliance-matrix.md` already exists with 14+ core RFC mappings, section-level citations, and implementation file references. Phase 28 extends it.
- **Add NIST SP cross-references.** SP 800-63B (AAL alignment), SP 800-88 Rev 1 (secure deletion), SP 800-115 (security testing methodology). Already partially covered in `docs/security-guide.md` — consolidate into the matrix.
- **Add SOC 2 control mapping.** Cross-reference SOC 2 Trust Service Criteria to implementation. Already partially in `docs/security-guide.md`.
- **Verify implementation status for every protocol claim.** Audit each row — confirm "Full/Partial/Planned" status matches current codebase state after v2.2 hardening phases.
- **Extremely detailed for all audiences.** Auditors, security reviewers, conference submissions, IETF WG engagement.

### Identity Rationalization Guide (DOC-02)
- **Target audience: enterprise identity admins** deploying unix-oidc alongside existing Active Directory / FreeIPA infrastructure.
- **SSSD-only model is the design anchor.** Groups resolved from SSSD/NSS, NOT from OIDC token claims (Phase 8 decision). FreeIPA is source of truth. GroupSource::TokenClaim was removed as dead code (Phase 26).
- **FreeIPA + Entra coexistence patterns.** How to configure unix-oidc when both FreeIPA and Entra ID are in play — trust boundaries, user object mapping, group sync strategies.
- **UPN-to-uid mapping examples.** Concrete worked examples showing how Entra UPNs (user@domain.com) map to Unix UIDs via SSSD/FreeIPA.
- **Group sync strategies.** IPA-AD trust vs SSSD multi-domain vs manual sync. Pros/cons/recommendations.
- **Extremely detailed.** Worked examples, configuration snippets, troubleshooting section.

### JTI Cache Architecture (DOC-03)
- **Internal architecture + operator-facing explainer.** Both audiences served in one doc with layered sections.
- **Per-process cache in forked-sshd model.** Each sshd fork gets its own process — no shared memory. Explain why this is sufficient for replay protection at the SSH authentication boundary.
- **DPoP nonces as actual replay defense.** JTI cache is a belt; DPoP nonce exchange is the suspenders. Document how the two-round nonce protocol makes JTI replay protection redundant for the DPoP proof itself, while JTI still protects the access token.
- **Why distributed cache (Redis) is out of scope.** The forked-sshd model means each auth attempt is a fresh process — a distributed JTI cache adds complexity without security benefit in this architecture. Document this explicitly to prevent future feature requests.

### E2E Test Strategy (E2ET-01 through E2ET-05)
- **Build on existing infrastructure.** Docker Compose (Keycloak 24.0 + OpenLDAP + test-host), existing shell scripts in `test/tests/`, Playwright in `test/e2e/`. Don't reinvent.
- **Shell scripts for PAM/SSH E2E tests.** The existing pattern (test_dpop_e2e.sh, test_break_glass_fallback.sh, etc.) is the right approach for testing PAM flows that need real sshd processes.
- **CIBA E2E: Keycloak for CI, external IdP for manual.** Enable CIBA in existing Keycloak realm config for automated CI. Document manual procedure for external IdP (Entra) verification as companion.
- **FIDO2 ACR delegation in Keycloak.** Configure Keycloak authentication flow to simulate FIDO2 ACR levels for automated testing. Real FIDO2 hardware is manual-only.
- **systemd E2E in Docker, launchd as local macOS script.** systemd socket activation tested in CI via systemd-enabled Docker container. launchd install/uninstall is a standalone script for local macOS execution — not in CI. Both documented.
- **CI wiring.** New E2E tests should integrate into existing CI workflows (`ci.yml` or dedicated E2E workflow). Tests that need Docker Compose should use the existing `docker-compose.test.yaml` or extend it.

### Claude's Discretion
- Exact test script structure and assertion patterns
- Whether to refactor existing shell scripts for consistency or write new ones alongside
- Docker Compose service additions needed for systemd testing
- Ordering and grouping of E2E tests in CI

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing documentation (update targets)
- `docs/standards-compliance-matrix.md` — Current RFC/NIST/framework matrix to update for DOC-01
- `docs/security-guide.md` — Has partial NIST SP 800-63B AAL mapping and SOC2 controls (consolidate into matrix)
- `docs/storage-architecture.md` — Storage backend docs with NIST SP 800-88 references

### Identity architecture
- `docs/entra-setup-guide.md` — Entra ID integration setup (reference for DOC-02 identity rationalization)
- `pam-unix-oidc/src/oidc/username.rs` — Username mapping implementation (UPN-to-uid)
- `pam-unix-oidc/src/policy/config.rs` — Multi-issuer config including group policy

### JTI and DPoP architecture
- `pam-unix-oidc/src/oidc/dpop.rs` — DPoP validation with JTI cache and nonce exchange
- `pam-unix-oidc/src/oidc/validation.rs` — Token validation pipeline with JTI enforcement
- `CLAUDE.md` §"DPoP Validation" — Security invariants for JTI replay protection

### Existing E2E tests and infrastructure
- `docs/integration-testing-assessment.md` — Comprehensive gap analysis of current test coverage
- `test/tests/test_dpop_e2e.sh` — Existing DPoP E2E test (starting point for E2ET-01)
- `test/tests/test_break_glass_fallback.sh` — Existing break-glass test (starting point for E2ET-02)
- `test/tests/test_ciba_integration.sh` — Existing CIBA test (starting point for E2ET-04)
- `test/e2e/playwright.config.ts` — Playwright setup for browser-based E2E
- `test/docker/` — Docker Compose test infrastructure

### CI workflows
- `.github/workflows/ci.yml` — Main CI pipeline (integration test stage)
- `.github/workflows/integration-multiarch.yml` — Multi-arch integration tests

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `test/tests/*.sh` — 12+ existing test scripts with established patterns (assertion helpers, Docker Compose lifecycle, Keycloak token acquisition)
- `test/e2e/` — Playwright setup with `run-device-flow-e2e.sh` orchestrator
- `test/docker/` — Docker Compose configs for Keycloak + OpenLDAP + test-host
- `test/scripts/run-integration-tests.sh` — Test runner infrastructure

### Established Patterns
- Shell-based E2E tests use `docker compose exec test-host` to run assertions inside the test container
- Keycloak tokens acquired via ROPC or device flow grant for test setup
- Integration tests gated by `docker compose up -d` lifecycle in CI
- Standards matrix uses pipe-delimited table format with RFC/Title/Sections/Files/Status/Notes columns

### Integration Points
- New E2E tests wire into `.github/workflows/ci.yml` integration stage
- Keycloak realm config in `test/docker/` needs CIBA enablement
- systemd testing needs a systemd-enabled Docker image (e.g., `jrei/systemd-ubuntu`)
- launchd script standalone — no CI integration needed

</code_context>

<specifics>
## Specific Ideas

- Standards matrix should serve publications pipeline: whitepapers, conference talks, IETF WG outreach, blog posts (from memory/standards-tracking.md)
- Identity rationalization guide should address the "archaeology problem" — finding all access when someone leaves
- JTI architecture doc should preempt the "why not Redis?" question with clear architectural reasoning

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 28-documentation-e2e-test-coverage*
*Context gathered: 2026-03-16*
