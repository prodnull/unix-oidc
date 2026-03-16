---
phase: 28-documentation-e2e-test-coverage
plan: "06"
subsystem: test-infrastructure
tags: [e2e, gap-closure, docker, policy, nss-group-policy, E2ET-02]
dependency_graph:
  requires: []
  provides: [E2ET-02-closed]
  affects: [test/docker/Dockerfile.test-host, test/fixtures/policy/policy-break-glass-e2e.yaml, docker-compose.test.yaml, test/tests/test_break_glass_e2e.sh]
tech_stack:
  added: []
  patterns: [volume-override-policy, dockerfile-group-isolation, skip-to-fail-promotion]
key_files:
  created:
    - test/fixtures/policy/policy-break-glass-e2e.yaml
  modified:
    - test/docker/Dockerfile.test-host
    - docker-compose.test.yaml
    - test/tests/test_break_glass_e2e.sh
decisions:
  - "testuser2 created with no supplemental groups via useradd -G '' — ensures NSS getgrouplist returns only the private group testuser2"
  - "Policy fixture volume-mounted at runtime (not baked in image) — allows policy scenarios without Dockerfile rebuild"
  - "Missing testuser2 promotes from SKIP to FAIL — container image build invariant, not optional configuration"
metrics:
  duration_minutes: 30
  completed_date: "2026-03-16"
  tasks_completed: 2
  files_changed: 4
---

# Phase 28 Plan 06: E2ET-02 NSS Group Policy Denial — Gap Closure Summary

One-liner: Closes E2ET-02 by adding testuser2 + unix_oidc_users group to the Docker test infrastructure and promoting Test 2 from permanent SKIP to active assertion.

## What Was Done

E2ET-02 Test 2 (NSS group policy denial) had been silently SKIPping in CI because testuser2 did not exist in the test-host container and no policy fixture restricted login_groups. This plan closes that gap in two atomic tasks.

### Task 1: Dockerfile + Policy Fixture (commit 8648e29)

**Dockerfile.test-host** — After the existing `testuser` creation:
- `groupadd unix_oidc_users` — creates the NSS group the PAM module checks
- `usermod -aG unix_oidc_users testuser` — testuser can authenticate (Test 3 positive)
- `useradd -m -s /bin/bash -G "" testuser2` — testuser2 gets only its private group; `getgrouplist("testuser2")` never returns `unix_oidc_users`

**test/fixtures/policy/policy-break-glass-e2e.yaml** (new file):
- `ssh_login.login_groups: [unix_oidc_users]` — restricts SSH login to members of that group
- `break_glass.alert_on_use: true` — required for Test 1 to confirm BREAK_GLASS_AUTH at CRITICAL severity (Phase 24-01 decision)
- All other fields mirror `policy-e2e.yaml` structure (same enforcement modes, cache, timeouts)

Verified inside container:
```
uid=1001(testuser2) gid=1002(testuser2) groups=1002(testuser2)   ← no unix_oidc_users
testuser : testuser unix_oidc_users                               ← testuser is a member
GROUPS_CORRECT
```

### Task 2: Compose Wire-up + SKIP Removal (commit e97ffb6)

**docker-compose.test.yaml** — Added volume mount to test-host service:
```yaml
- ./test/fixtures/policy/policy-break-glass-e2e.yaml:/etc/unix-oidc/policy.yaml:ro
```
This overlays the policy baked into the image at build time with the break-glass fixture that includes `login_groups`. No image rebuild required when switching policy scenarios.

**test/tests/test_break_glass_e2e.sh** — Two changes:

1. Comment block at top (lines 52-56): removed TODO, replaced with factual description pointing to the fixture and compose mount.

2. Test 2 SKIP guard (lines 240-245): replaced the multi-line `skip + TODO echo` block with a single `fail` call:
```bash
# Before:
if [ "$TESTUSER2_EXISTS" = false ]; then
    skip "User $NORMAL_USER_NOT_IN_GROUP not found in container"
    echo "    # TODO: configure ..."
    ...

# After:
if [ "$TESTUSER2_EXISTS" = false ]; then
    fail "User $NORMAL_USER_NOT_IN_GROUP not found in container — Dockerfile.test-host must create this user (see E2ET-02 gap closure plan 28-06)"
```

Rationale: testuser2 is now a build invariant. A stale image (built before this change) would cause `TESTUSER2_EXISTS=false` — which should be a visible CI failure, not a silent SKIP.

## Verification

```bash
bash -n test/tests/test_break_glass_e2e.sh   # SYNTAX_OK
grep -c "TODO: configure testuser2" test/tests/test_break_glass_e2e.sh  # 0
grep "policy-break-glass-e2e" docker-compose.test.yaml  # 1 match (volume line)
```

Container runtime verification:
```
GROUPS_CORRECT
POLICY_OK (login_groups present in mounted policy)
```

## Deviations from Plan

None — plan executed exactly as written.

## Requirement Status

**E2ET-02: CLOSED** — NSS group policy denial now executes in CI. Test 2 asserts denial (or fails with clear message) rather than silently skipping. The SKIP branch has been eliminated; the only remaining SKIP paths are infrastructure-level (docker not available, compose stack not running) which are appropriate guards for the CI environment bootstrapping phase.

## Self-Check: PASSED

Files verified to exist:
- test/fixtures/policy/policy-break-glass-e2e.yaml: FOUND
- test/docker/Dockerfile.test-host (contains testuser2): FOUND
- docker-compose.test.yaml (contains policy-break-glass-e2e.yaml mount): FOUND
- test/tests/test_break_glass_e2e.sh (no TODO for testuser2, SKIP removed): FOUND

Commits verified:
- 8648e29: feat(28-06): add testuser2 + unix_oidc_users group for E2ET-02 group policy denial test
- e97ffb6: feat(28-06): wire policy fixture into compose and promote Test 2 SKIP to FAIL/ASSERT
