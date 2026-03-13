# Stack Research: v2.1 Integration Testing Infrastructure

**Domain:** E2E integration testing with real OIDC IdPs — Keycloak DPoP, Playwright device flow CI, Azure Entra ID
**Researched:** 2026-03-13
**Confidence:** MEDIUM-HIGH overall (Keycloak DPoP: HIGH, Playwright: HIGH, Entra ID DPoP: LOW — see notes)

---

## Scope: Delta Only

The v1.0/v2.0 stack (Rust 1.88, tokio, reqwest 0.11, p256 0.13, keyring, zeroize, secrecy, tracing, Docker Compose, 14 shell integration scripts) is validated and unchanged. This file covers **only the new additions** required for v2.1: real-signature E2E testing without `UNIX_OIDC_TEST_MODE`, Playwright-based device flow automation in CI, and Azure Entra ID integration tests.

---

## Recommended Stack

### Core Technologies (NEW for v2.1)

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Keycloak Docker | `quay.io/keycloak/keycloak:26.4` | DPoP-capable IdP for real-signature tests | 26.4 is the first GA DPoP release (official since 2025-10); current pinned `24.0` has DPoP as an unfinished preview — `cnf.jkt` claim behavior is undefined in device flow at 24.x |
| `@playwright/test` | `1.58.2` | Device flow browser automation in CI | Headless Chromium in GitHub Actions `ubuntu-latest` with no extra infrastructure; existing `demo/` already uses 1.48, v2.1 upgrades and formalizes it |
| Node.js LTS | `24.x` (v24.14.0 "Krypton") | Playwright test runtime | Current LTS; Playwright recommends `node-version: lts/*` in GHA |
| `testcontainers` (Rust) | `0.27.1` | Spin up Keycloak container inside `#[tokio::test]` | Enables real-signature Rust tests gated with `#[ignore = "requires Docker"]` without a separate shell-level compose lifecycle; integrates with cargo test parallelism |
| `keycloak` (Rust admin crate) | `26.5.200` | Keycloak Admin REST API for realm/user setup in tests | Admin API crate that mirrors server version; lets Rust tests provision users, rotate signing keys, and verify JWKS mid-test |

### Supporting Libraries (NEW for v2.1)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `reqwest` | `0.13.2` | JWKS fetch and token polling in Rust test helpers | **Version upgrade from 0.11.x** — required for testcontainers integration; audit all `ClientBuilder` TLS/redirect configs during upgrade; use `redirect::Policy::none()` on JWKS client |
| `jsonwebtoken` | `9.x` | Decode and inspect real tokens in test-side assertions | Test-only; never in production PAM path; used to verify `cnf.jkt`, `preferred_username`, `iss`, `aud` claims are present and correct in tokens received from live Keycloak |
| `testcontainers-modules` | `0.15.0` | Community modules crate — included for `openldap` feature | No Keycloak module exists in 0.15.0; use generic `testcontainers` + `GenericImage::new("quay.io/keycloak/keycloak", "26.4")` for Keycloak; the `openldap` feature replaces shell-level LDAP setup in Rust tests |

### Development Tools (NEW for v2.1)

| Tool | Purpose | Notes |
|------|---------|-------|
| `npx playwright install chromium --with-deps --only-shell` | Install headless Chromium for CI | `--only-shell` skips the headed build (~300 MB saved); run fresh on each CI job — do not cache browser binaries (Playwright docs explicitly advise against it: restore time equals download time) |
| `playwright.config.ts` | Playwright test config in `test/e2e/` | Set `workers: process.env.CI ? 1 : undefined`; device flow is sequential by nature; screenshot on failure with `screenshot: 'only-on-failure'`; upload `playwright-report/` artifact 30-day retention |

---

## Installation

```bash
# Playwright test suite — new directory: test/e2e/
cd test/e2e
npm init -y
npm install -D @playwright/test@1.58.2
npx playwright install chromium --with-deps --only-shell

# Rust test-side — add to pam-unix-oidc/Cargo.toml or workspace [dev-dependencies]
# testcontainers = "0.27.1"
# testcontainers-modules = { version = "0.15.0", features = ["openldap"] }
# keycloak = "26.5.200"
# jsonwebtoken = "9"

# Rust reqwest upgrade — change in workspace Cargo.toml
# reqwest = { version = "0.13.2", features = ["json", "rustls-tls"], default-features = false }
```

```yaml
# docker-compose.test.yaml — change only this line
image: quay.io/keycloak/keycloak:26.4   # was 24.0
```

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Keycloak 26.4 | Stay on Keycloak 24.0 | Never for DPoP tests — 24.0 DPoP is preview/undocumented; `cnf.jkt` in device flow tokens not guaranteed |
| Keycloak 26.4 | Keycloak 26.5.5 (latest available) | Acceptable — 26.5.5 is stable; pin to 26.4 for reproducibility, or 26.5.5 for latest security fixes; test realm JSON import at both |
| `@playwright/test` TypeScript | `puppeteer`, Selenium | Playwright is the current standard for headless CI; Puppeteer lacks Keycloak login form robustness in headless-new mode; Selenium is heavier and GHA setup is fragile |
| `@playwright/test` TypeScript | Rust `headless_chrome` crate | `headless_chrome` is low-maintenance and not suited for interactive OIDC consent sequences; TypeScript Playwright has native multi-step form support |
| `testcontainers` Rust | Extend shell scripts | Shell scripts cannot be gated per-test with `#[ignore]`; testcontainers integrates with cargo test lifecycle, allows parallel test isolation, and enables programmatic container inspection |
| Generic Keycloak image in testcontainers | `testcontainers-modules` Keycloak feature | No Keycloak feature exists in `testcontainers-modules` 0.15.0 — use `GenericImage` directly |
| Entra ID: JWKS/discovery-only first | Full device flow E2E with Entra | Entra device flow with DPoP is UNCONFIRMED — gate deeper Entra tests behind secret availability AND confirmed DPoP support; JWKS/discovery validation requires no credentials |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `UNIX_OIDC_TEST_MODE=true` in NEW tests | Completely bypasses signature verification — the entire purpose of v2.1 is to eliminate this bypass; existing `24.0`-era tests may keep it as fallback but no new test should use it | Real Keycloak 26.4 tokens with JWKS verification |
| Keycloak 24.0 for DPoP tests | DPoP was preview-only in 23.x/24.x; `cnf.jkt` claim not reliably present in device flow tokens | `quay.io/keycloak/keycloak:26.4` |
| `dasniko/testcontainers-keycloak` | Java-only library; no Rust bindings | Generic `testcontainers::GenericImage` in Rust |
| `playwright-github-action` (marketplace action) | Deprecated by Microsoft; their own docs now recommend CLI | `npx playwright install --with-deps` directly in workflow steps |
| Caching Playwright browser binaries in GHA | Playwright's own docs: "not recommended — restore time is comparable to download time" | Skip cache; use `--only-shell` to minimize download size |
| `@playwright/test` in `dependencies` | Browser automation is test-only | `devDependencies` only |
| Entra ID as the primary DPoP test target | DPoP support for Entra ID device code flow is unconfirmed as of 2026-03-13; MSAL-JS issue #5979 (2023) had no resolved answer; Entra tokens use RS256, not ES256 — different validation code path | Use Keycloak 26.4 as the DPoP test baseline; add Entra as JWKS/discovery-only until DPoP status confirmed officially |
| `reqwest 0.11` for new test code | 0.11 reaches end of active maintenance; `testcontainers` async integration expects 0.12+; 0.13.2 is current stable | `reqwest 0.13.2` with `rustls-tls` feature for test helpers |

---

## Stack Patterns by Variant

**Real-signature Keycloak tests (primary v2.1 path):**
- Keycloak 26.4 docker image
- Realm JSON: `dpop.bound.access.tokens: true` on client (already set); verify `deviceAuthorizationGrantEnabled: true` at client level (currently `false` — fix required)
- Playwright: navigate to `verification_uri_complete` → type credentials → click submit; poll `/token` endpoint until `access_token` returned
- PAM module: receives token with `cnf.jkt` claim; fetches JWKS from Keycloak; verifies ES256 signature; validates cnf binding against DPoP proof
- No `UNIX_OIDC_TEST_MODE` — this is the whole point

**Playwright in GitHub Actions:**
```yaml
- uses: actions/setup-node@v6
  with:
    node-version: lts/*
- run: npm ci
  working-directory: test/e2e
- run: npx playwright install chromium --with-deps --only-shell
  working-directory: test/e2e
- run: npx playwright test
  working-directory: test/e2e
  env:
    KEYCLOAK_URL: http://localhost:8080
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: playwright-report
    path: test/e2e/playwright-report/
    retention-days: 30
```

**Azure Entra ID tests (gated, JWKS/discovery only first):**
- Issuer URL: `https://login.microsoftonline.com/{tenant_id}/v2.0`
- JWKS endpoint: `https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys`
- Token signing algorithm: RS256 (RSA, NOT EC) — PAM module must handle RS256; verify `jsonwebtoken` validation handles both RS256 and ES256 before Entra work starts
- `preferred_username` claim: requires `profile` scope; must be added to optional claims in app registration if absent
- Gate entire job behind `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` secrets; skip gracefully if not configured
- `verification_uri_complete` NOT supported by Entra device flow — Playwright must navigate to `verification_uri` + enter `user_code` separately

---

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `@playwright/test@1.58.2` | Node.js 18+, `ubuntu-latest` GHA | Upgrade from `1.48.0` in `demo/`; no breaking API changes in minor versions; existing `demo/` tests remain unaffected |
| `testcontainers@0.27.1` | `tokio 1.x` async runtime | Use `#[tokio::test]` attribute; `testcontainers` drives containers via tokio runtime; existing workspace tokio version compatible |
| `keycloak@26.5.200` | Keycloak server 26.4 | Admin API crate version mirrors server; 26.5.200 against 26.4 server is minor-version compatible for all v26 Admin API calls |
| `quay.io/keycloak/keycloak:26.4` | Existing realm JSON format | Realm import format stable; verify `deviceAuthorizationGrantEnabled` client field vs. attribute string — 26.x may prefer the boolean field |
| `reqwest@0.13.2` | Existing PAM module code using 0.11 | Breaking: upgrade ALL workspace crates simultaneously; `reqwest::Client` API stable but TLS defaults changed; `rustls-tls` feature recommended over `native-tls`; redirect policy API unchanged |
| Entra ID JWKS (RS256 keys) | PAM module JWKS validation | PAM module currently tested only against ES256 (Keycloak); must verify RS256 code path works before claiming Entra support |

---

## Critical Prerequisite: Keycloak Image Upgrade

The current `docker-compose.test.yaml` pins `quay.io/keycloak/keycloak:24.0`. The realm JSON already sets `dpop.bound.access.tokens: true` on the client, but this attribute has no reliable effect in 24.x — DPoP was a preview feature with gaps specifically in device flow.

Keycloak 26.4 (released September 2025, DPoP GA announced October 2025) is required for:
- Reliable `cnf.jkt` claim in device flow access tokens
- `fapi-2-dpop-security-profile` client profile (optional but available)
- Securing all token endpoint calls with DPoP proofs

The latest available image as of research is `26.5.5`; pin to `26.4` for a stable baseline or `26.5.5` for latest security fixes. Both are acceptable.

**Action required in docker-compose.test.yaml:**
```yaml
image: quay.io/keycloak/keycloak:26.4   # upgrade from 24.0
```

**Action required in realm JSON:**
- Verify `deviceAuthorizationGrantEnabled: true` (boolean) is set at client level — the string attribute `oauth2.device.authorization.grant.enabled: "true"` may not be sufficient in 26.x; check import behavior.

## Critical Prerequisite: reqwest Upgrade Scope

Upgrading from `reqwest 0.11` to `0.13.2` is a workspace-wide change that touches all HTTP client code. Audit checklist:
1. `redirect::Policy::none()` — confirm this is still set on JWKS client (SSRF protection)
2. TLS: switch from `native-tls` to `rustls-tls` feature (preferred for PAM module builds)
3. `ClientBuilder::timeout()` — API unchanged but verify all production timeouts are still set
4. JWKS cache client — must not follow redirects, must validate TLS certificates to expected host

---

## Sources

- Keycloak 26.4 DPoP GA announcement — [keycloak.org/2025/10/dpop-support-26-4](https://www.keycloak.org/2025/10/dpop-support-26-4) — HIGH confidence
- Keycloak 26.4.0 release — [keycloak.org/2025/09/keycloak-2640-released](https://www.keycloak.org/2025/09/keycloak-2640-released) — HIGH confidence
- quay.io Keycloak tags — latest `26.5.5` confirmed — HIGH confidence
- Playwright CI docs — [playwright.dev/docs/ci](https://playwright.dev/docs/ci) — HIGH confidence (official)
- Playwright 1.58.2 on npm — [npmjs.com/package/playwright](https://www.npmjs.com/package/playwright) — HIGH confidence
- Playwright browser caching advisory (do not cache) — [playwright.dev/docs/ci](https://playwright.dev/docs/ci) — HIGH confidence
- `testcontainers` 0.27.1 — [crates.io API](https://crates.io/crates/testcontainers) — HIGH confidence (API verified)
- `testcontainers-modules` 0.15.0, no Keycloak module — [Cargo.toml verified](https://raw.githubusercontent.com/testcontainers/testcontainers-rs-modules-community/main/Cargo.toml) — HIGH confidence
- `keycloak` admin crate 26.5.200 — [crates.io API](https://crates.io/crates/keycloak) — HIGH confidence (API verified, updated 2026-02-08)
- `reqwest` 0.13.2 — [crates.io API](https://crates.io/crates/reqwest) — HIGH confidence
- Node.js 24.x LTS — [nodejs.org dist/index.json](https://nodejs.org/dist/index.json) — HIGH confidence
- Entra ID OIDC docs (issuer, JWKS URL format, RS256 algorithm) — [learn.microsoft.com/entra/identity-platform/v2-protocols-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) — HIGH confidence for URL/algorithm; LOW for DPoP device flow support
- Entra ID device code flow — [learn.microsoft.com](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) — HIGH confidence for protocol; note: `verification_uri_complete` explicitly NOT supported
- MSAL-JS DPoP issue — [github.com/AzureAD/microsoft-authentication-library-for-js/issues/5979](https://github.com/AzureAD/microsoft-authentication-library-for-js/issues/5979) — LOW confidence signal (unresolved 2023 request, no 2025 followup found)
- Existing realm JSON inspection — `test/fixtures/keycloak/unix-oidc-test-realm.json` — confirmed `dpop.bound.access.tokens: true`, `oauth2.device.authorization.grant.enabled: "true"`, `deviceAuthorizationGrantEnabled: false` (bug — must be fixed)

---

*Stack research for: unix-oidc v2.1 Integration Testing Infrastructure*
*Researched: 2026-03-13*
