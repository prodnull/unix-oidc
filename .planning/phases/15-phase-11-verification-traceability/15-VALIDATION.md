---
phase: 15
slug: phase-11-verification-traceability
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-12
---

# Phase 15 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Shell (bash) + Python + Docker Compose + cargo test |
| **Config file** | `docker-compose.token-exchange.yaml` |
| **Quick run command** | `cargo test --workspace` |
| **Full suite command** | `docker compose -f docker-compose.token-exchange.yaml up -d && bash test/tests/test_token_exchange.sh && python3 test/tests/test_token_exchange.py && bash test/tests/test_dpop_binding.sh && docker compose -f docker-compose.token-exchange.yaml down -v` |
| **Estimated runtime** | ~120 seconds (Keycloak startup dominates) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace`
- **After every plan wave:** Run full docker-compose suite (all three test scripts)
- **Before `/gsd:verify-work`:** Full suite must be green + CI `token-exchange` job green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 15-01-01 | 01 | 1 | TEST-01 | integration | `bash test/tests/test_token_exchange.sh` (requires docker-compose up) | ✅ | ⬜ pending |
| 15-01-02 | 01 | 1 | TEST-01 | integration | `python3 test/tests/test_token_exchange.py` (requires docker-compose up) | ✅ | ⬜ pending |
| 15-01-03 | 01 | 1 | TEST-02 | integration | `bash test/tests/test_dpop_binding.sh` (requires docker-compose up) | ✅ | ⬜ pending |
| 15-01-04 | 01 | 1 | TEST-01, TEST-02 | CI gate | `gh run view <id> --job token-exchange` | ✅ | ⬜ pending |
| 15-02-01 | 02 | 2 | TEST-01, TEST-02 | documentation | manual: verify REQUIREMENTS.md checkboxes + traceability table | ✅ | ⬜ pending |
| 15-02-02 | 02 | 2 | TEST-01, TEST-02 | documentation | manual: verify ROADMAP.md Phase 11 status + plan checkboxes | ✅ | ⬜ pending |
| 15-02-03 | 02 | 2 | TEST-01, TEST-02 | documentation | manual: verify 11-VERIFICATION.md exists and is complete | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test files need to be created.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| REQUIREMENTS.md traceability correctness | TEST-01, TEST-02 | Documentation audit — no code to test | Verify `[x]` checkboxes, Phase column = 11, Status = Complete |
| ROADMAP.md Phase 11 status | TEST-01, TEST-02 | Documentation audit — no code to test | Verify progress row shows 2/2 Complete, plan checkboxes checked |
| 11-VERIFICATION.md completeness | TEST-01, TEST-02 | Document creation — verified by review | Verify table has all 4 TEST-* rows with evidence |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
