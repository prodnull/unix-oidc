---
phase: 29-keycloak-dpop-verification
reviewed: 2026-04-07T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - .github/workflows/ci.yml
  - docs/keycloak-dpop-reference.md
  - pam-unix-oidc/src/audit.rs
  - pam-unix-oidc/src/lib.rs
  - test/tests/test_dpop_pam_audit.sh
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 29: Code Review Report

**Reviewed:** 2026-04-07T00:00:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

This phase introduces the Keycloak DPoP verification integration: a reference document,
an audit event integration test (KCDPOP-02), and supporting changes to `audit.rs` and
`lib.rs`. The PAM core logic and audit chain are well-structured. One critical finding
concerns the IPC message format in `lib.rs` — a `session_id` value containing a
double-quote character can corrupt the JSON sent to the agent, potentially causing
revocation to silently fail. Four warnings cover: test gates silenced with `|| true`
in CI, an environment variable inconsistency in the shell test, a missing `xxd` dependency
in the `keycloak-e2e` CI job that runs `test_dpop_pam_audit.sh`, and the DPoP signature
in the shell test being raw DER rather than the IEEE P1363 format required by RFC 9449.
Three info items cover: a TODO comment left in CI, a hardcoded `CLIENT_SECRET` default in
the test script, and the `is_base64url` helper not guarding against the base64 `+`/`/`
alphabet.

---

## Critical Issues

### CR-01: IPC JSON message uses string interpolation — session_id injection breaks JSON

**File:** `pam-unix-oidc/src/lib.rs:757`

**Issue:** The agent IPC message is built with a raw format string:

```rust
let msg = format!(r#"{{"action":"session_closed","session_id":"{session_id}"}}"#);
```

`session_id` is generated internally by `uuid` (or equivalent) in the happy path, but
it is sourced from `pamh.getenv("UNIX_OIDC_SESSION_ID")` in `close_session` (line 643).
PAM environment variables can be influenced by a user who controls their own session
environment. A value such as `","foo":"bar` would produce malformed JSON, causing the
agent's `BufReader::read_line` JSON parse to fail, silently dropping the revocation
notification. Because the IPC path is already best-effort and the failure is only logged
at DEBUG (`Agent IPC ACK not received`), this can suppress revocation without any
operator-visible signal. The write-failure path does emit `SESSION_CLOSE_FAILED`, but a
malformed message that is successfully written does not.

**Fix:** Use `serde_json` to serialize the message rather than string interpolation:

```rust
use serde_json::json;
let msg = serde_json::to_string(&json!({
    "action": "session_closed",
    "session_id": session_id
}))
.unwrap_or_default();
```

This eliminates injection regardless of the session_id content and is already a
transitive dependency.

---

## Warnings

### WR-01: Multiple E2E test steps silenced with `|| true` — failures are invisible to CI

**File:** `.github/workflows/ci.yml:209,211,237,495`

**Issue:** Four E2E test invocations use `|| true`:

```yaml
bash test/tests/test_dpop_nonce_e2e.sh || true   # line 209
bash test/tests/test_break_glass_e2e.sh || true  # line 211
bash test/tests/test_session_lifecycle_e2e.sh || true  # line 237
bash test/tests/test_systemd_launchd_e2e.sh || true    # line 495
```

This means failures in these tests never fail the CI run. The `# TODO: remove || true`
comments indicate this is known-temporary, but there is no tracking issue or expiry date.
Security-relevant tests (DPoP nonce E2E, break-glass E2E) silently passing when broken
defeats their purpose.

**Fix:** Remove `|| true` from all security-path tests (E2ET-01, E2ET-02, E2ET-03).
If the compose environment is genuinely unstable, convert those steps to use
`continue-on-error: true` with an explicit `if: failure()` step that prints a prominent
warning, so failures are visible in the job summary even when not blocking. For E2ET-05
(systemd), `continue-on-error: true` is more defensible given the privileged container
constraints, but must still emit a summary line.

---

### WR-02: `test_dpop_pam_audit.sh` uses inconsistent environment variable names

**File:** `test/tests/test_dpop_pam_audit.sh:32-33`

**Issue:** The script reads `KEYCLOAK_REALM` and `KEYCLOAK_CLIENT_ID`:

```bash
REALM="${KEYCLOAK_REALM:-unix-oidc}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-unix-oidc}"
```

The `keycloak-e2e` job in `ci.yml` (lines 415-419) sets `REALM` and `CLIENT_ID` directly
(without the `KEYCLOAK_` prefix) as environment variables when calling
`test_dpop_binding.sh`. If the same env-var convention is expected for
`test_dpop_pam_audit.sh`, callers must set `KEYCLOAK_REALM` / `KEYCLOAK_CLIENT_ID`
rather than the bare `REALM` / `CLIENT_ID`. This means any CI job that invokes
`test_dpop_pam_audit.sh` passing `REALM=...` will have the variable ignored and the
default used silently.

**Fix:** Align with the convention used in `test_dpop_binding.sh` (which the CI job
already sets). Either accept both forms or document the required variable name clearly
in the script header. The safest fix is to accept both:

```bash
REALM="${KEYCLOAK_REALM:-${REALM:-unix-oidc}}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-${CLIENT_ID:-unix-oidc}}"
```

---

### WR-03: DPoP proof signature uses raw DER encoding — not valid per RFC 9449

**File:** `test/tests/test_dpop_pam_audit.sh:115-117`

**Issue:** The DPoP proof signature is generated as:

```bash
SIGNATURE=$(printf '%s' "$SIGNING_INPUT" | \
    openssl dgst -sha256 -sign "$TMPDIR_KEYS/ec_private.pem" | \
    base64url_encode)
```

`openssl dgst -sign` with an EC key produces a DER-encoded ECDSA signature (ASN.1
SEQUENCE of two INTEGERs). RFC 9449 §4.2 requires JWS signatures to use the IEEE P1363
fixed-width format (two 32-byte big-endian integers concatenated, total 64 bytes for
P-256). The DER encoding is variable-length and will not decode correctly by any
conformant JWT library, including the Rust `jsonwebtoken` crate used in the PAM module.

As a result, the PAM module will reject the DPoP proof with a signature error, and
Step 7 of the test will never produce a valid `SSH_LOGIN_SUCCESS` event. The test
currently acknowledges this may happen ("SSH session did not complete (expected if PAM
not fully configured for E2E)"), but the underlying cause is the wrong signature
encoding, not PAM configuration.

**Fix:** Convert from DER to IEEE P1363 before base64url encoding. With `openssl` and
`xxd` this requires extracting the r and s integers from the ASN.1 structure and
zero-padding each to 32 bytes. Alternatively use a Python helper (already a dependency
in `token-exchange`) with `cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature`.

---

### WR-04: `keycloak-e2e` CI job missing `xxd` dependency required by `test_dpop_pam_audit.sh`

**File:** `.github/workflows/ci.yml:359-361`

**Issue:** The `keycloak-e2e` job installs:

```yaml
run: sudo apt-get update && sudo apt-get install -y curl jq openssh-client python3
```

`test_dpop_pam_audit.sh` calls `hex_to_base64url()` which uses `xxd` (line 84). `xxd`
is part of the `vim-common` package and is not guaranteed present on `ubuntu-24.04`
runners. The `token-exchange` job (line 258) correctly installs `xxd`, but the
`keycloak-e2e` job does not. If `test_dpop_pam_audit.sh` is added to the `keycloak-e2e`
job (which is the natural home for KCDPOP-02), it will fail silently because
`hex_to_base64url` will produce empty output without erroring — `xxd` is piped, not
checked.

**Fix:** Add `xxd` to the `keycloak-e2e` install step:

```yaml
run: sudo apt-get update && sudo apt-get install -y curl jq openssh-client python3 xxd
```

Also add `test_dpop_pam_audit.sh` to the `Make test scripts executable` step and invoke
it in the job body.

---

## Info

### IN-01: TODO comment in CI with no associated issue

**File:** `.github/workflows/ci.yml:207`

**Issue:** `# TODO: remove || true once test environment is confirmed passing` appears
three times without a GitHub issue reference. TODOs in CI are easy to forget.

**Fix:** Add an issue reference: `# TODO(#NNN): remove || true ...` so the cleanup
is tracked and searchable.

---

### IN-02: Hardcoded `CLIENT_SECRET` default in test script

**File:** `test/tests/test_dpop_pam_audit.sh:34`

**Issue:**

```bash
CLIENT_SECRET="${CLIENT_SECRET:-unix-oidc-test-secret}"
```

The secret is a known fixture value used in test environments only. It is not a
production secret. However, the variable name `CLIENT_SECRET` without a `KEYCLOAK_`
prefix (unlike `KEYCLOAK_REALM` and `KEYCLOAK_CLIENT_ID`) is inconsistent and could
lead to accidental collision with a caller's environment. This is info-level because
the value is a public test fixture, not a production credential.

**Fix:** Rename to `KEYCLOAK_CLIENT_SECRET` for consistency with the other
`KEYCLOAK_`-prefixed variables in this script.

---

### IN-03: `is_base64url` allows characters outside the base64url alphabet

**File:** `pam-unix-oidc/src/lib.rs:944-947`

**Issue:**

```rust
fn is_base64url(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
```

Base64url (RFC 4648 §5) uses `A-Z`, `a-z`, `0-9`, `-`, and `_`. This implementation
is correct. However, it also implicitly accepts base64 `+` and `/` characters because
`is_ascii_alphanumeric()` covers `0-9`, `A-Z`, `a-z` — not `+` or `/`. The concern is
the inverse: standard base64 uses `+` and `/` which are NOT accepted here, so a
non-base64url string (e.g. from a non-JWT source) that happens to contain only
alphanumeric characters and `-`/`_` would pass. This is a minor false-positive risk for
the `is_jwt` heuristic, not a security issue (full JWT validation happens downstream),
but worth noting for correctness.

**Fix:** No code change required. Consider adding a brief comment noting that the
function is an admission heuristic (not a security gate) and that full validation
occurs in the JWT parsing layer.

---

_Reviewed: 2026-04-07T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
