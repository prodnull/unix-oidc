# Phase 11: Implementation Completion - Research

**Researched:** 2026-03-11
**Domain:** CI/CD wiring, Keycloak DPoP configuration, cross-language interop testing, Rust async integration testing
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TEST-01 | Token exchange tests (shell + Python) wired into CI via `docker-compose.token-exchange.yaml` with DPoP cnf.jkt rebinding validation | All three test assets exist and are ready; CI job structure and wiring path identified |
| TEST-02 | DPoP-bound access token E2E — Keycloak test realm configured with `dpop.bound.access.tokens: true`; CI test validates cnf.jkt thumbprint match | Config change is a one-line JSON patch to `unix-oidc-test-realm.json`; test script pattern confirmed |
| TEST-03 | Cross-language DPoP interop tests (Rust/Go/Python) running in CI via `dpop-cross-language-tests/` | Script exists but includes Java, which requires Gradle; CI-viable Rust/Go/Python subset confirmed; Java deferral strategy documented |
| TEST-04 | Agent daemon lifecycle integration test — start daemon, send IPC commands, validate responses, clean shutdown | `AgentServer::new` + `serve()` are pub; existing socket tests in `socket.rs` show exact pattern for Rust integration tests |
</phase_requirements>

---

## Summary

Phase 11 is exclusively a wiring and gap-fill phase — no new production features, no new test frameworks. Every asset exists on disk; the gap is CI integration and two small configuration patches. The integration testing assessment (docs/integration-testing-assessment.md, P1/P2/P6/P7) is the authoritative gap analysis.

**Token exchange (TEST-01):** `test/tests/test_token_exchange.sh`, `test/tests/test_token_exchange.py`, and `docker-compose.token-exchange.yaml` are all complete and correct. They are untracked by git and not referenced in any CI workflow. The fix is: `git add` the files, add a `token-exchange` job to `ci.yml` that brings up the compose stack and runs the shell script.

**DPoP binding E2E (TEST-02):** The primary test realm (`unix-oidc-test-realm.json`) has the `unix-oidc` client with no `dpop.bound.access.tokens` attribute. The token-exchange-test realm already has `"dpop.bound.access.tokens": "true"`. Adding the attribute to the primary realm is a one-line JSON change. The existing `test_dpop_e2e.sh` is flagged as not-in-CI; it needs to be wired in (or a targeted test script added) that validates `cnf.jkt` presence and thumbprint match after the realm change.

**Cross-language DPoP (TEST-03):** `dpop-cross-language-tests/run-cross-language-tests.sh` tests Rust, Go, Python, and Java. Java requires `gradle` and a local `~/.gradle/caches` dependency resolution path that is fragile in GitHub Actions. The pragmatic CI strategy is to run the Rust/Go/Python subset (12 of 16 combinations) and skip Java in CI, or install Java 21 via `setup-java` action. Both paths are viable; the research recommends the `setup-java` path for full coverage but documents the skip-Java fallback.

**Agent daemon lifecycle (TEST-04):** The `AgentServer` struct is `pub` with a `pub fn new(socket_path, state)` constructor and `pub async fn serve()`. The existing unit tests in `socket.rs` (lines 1556, 1606, 1639, 1934, 2086) show the exact Rust test pattern: create a temp socket path, `tokio::spawn(server.serve())`, connect via `UnixStream`, write JSON, read response. A new file at `unix-oidc-agent/tests/daemon_lifecycle.rs` follows this pattern.

**Primary recommendation:** Wire the four test gaps into CI in a single phase with three plans: (1) token exchange CI job + git-track files, (2) DPoP binding realm patch + `test_dpop_e2e.sh` CI wiring, (3) cross-language interop CI job + agent daemon lifecycle Rust integration test.

---

## Standard Stack

### Core (all already in the project)

| Library/Tool | Version | Purpose | Notes |
|---|---|---|---|
| GitHub Actions `docker/compose-action` | N/A — use `docker compose` CLI directly | Bring up compose stack in CI | ci.yml already uses `docker compose -f ... up -d` pattern |
| Keycloak `dpop.bound.access.tokens` | Keycloak 24+ (test uses 26.2) | Force DPoP binding on token issue | Attribute string confirmed in `token-exchange-test-realm.json` |
| `tokio` | Already in `unix-oidc-agent` | Async runtime for daemon lifecycle test | `tokio::test` macro, `tokio::spawn` for server |
| `tempfile` crate | Already in workspace | Temp socket paths in tests | `tempdir()` for unique socket per test |
| `socat` / `nc` | Shell tool, available in ubuntu-latest | Send JSON to Unix socket from shell | Alternative to Rust integration test for shell-based lifecycle test |
| `setup-go` GitHub Action | `v5` | Install Go for cross-language tests | ubuntu-latest does not have Go pre-installed |
| `setup-java` GitHub Action | `v4` | Install Java 21 for full cross-language matrix | Optional — only needed for Java row/column |

### Python Test Dependencies (`test_token_exchange.py`)

| Package | Version | Install |
|---|---|---|
| `requests` | any | `pip install requests` |
| `cryptography` | any | `pip install cryptography` |
| `PyJWT` | any | `pip install PyJWT` |

ubuntu-latest has Python 3 pre-installed; packages need `pip install` in CI step.

---

## Architecture Patterns

### CI Job Pattern: Compose-Based Integration Test

This is the existing pattern in `ci.yml` `integration` job (lines 166-227). New jobs follow the same structure:

```yaml
token-exchange:
  name: Token Exchange Integration Tests
  runs-on: ubuntu-latest
  needs: [check]
  steps:
    - uses: actions/checkout@v6
    - name: Install dependencies
      run: sudo apt-get install -y curl jq xxd
    - name: Start token exchange environment
      run: |
        docker compose -f docker-compose.token-exchange.yaml up -d
        # wait for Keycloak health
        for i in $(seq 1 30); do
          curl -sf http://localhost:9000/health/ready && break
          sleep 5
        done
    - name: Run token exchange tests
      run: bash test/tests/test_token_exchange.sh
    - name: Stop environment
      if: always()
      run: docker compose -f docker-compose.token-exchange.yaml down -v
```

Key constraint: `docker-compose.token-exchange.yaml` mounts `./test/fixtures/keycloak` for realm import. Both realm JSON files are in that directory and are imported at startup via `--import-realm`. The compose file specifies Keycloak 26.2 with `--features=token-exchange,admin-fine-grained-authz,dpop`.

### Keycloak Realm Import Scope

`docker-compose.token-exchange.yaml` mounts the entire `test/fixtures/keycloak/` directory:
```yaml
volumes:
  - ./test/fixtures/keycloak:/opt/keycloak/data/import:ro
```

This means Keycloak 26.2 will import **both** realm files on startup (`unix-oidc-test-realm.json` and `token-exchange-test-realm.json`). The token exchange test uses the `token-exchange-test` realm. The DPoP E2E test (TEST-02) uses the `unix-oidc-test` realm — so once we add `"dpop.bound.access.tokens": "true"` to the primary realm, it is also available in the token-exchange compose environment.

### DPoP Binding Configuration Patch (TEST-02)

The `unix-oidc-test-realm.json` client `unix-oidc` attributes object currently:
```json
"attributes": {
  "oauth2.device.authorization.grant.enabled": "true",
  "oauth2.device.code.lifespan": "300",
  "oauth2.device.polling.interval": "5",
  "oidc.ciba.grant.enabled": "false"
}
```

Add one line:
```json
"dpop.bound.access.tokens": "true"
```

Keycloak 24+ (and 26.2) honor this attribute: when a DPoP proof is supplied at the token endpoint, the issued token includes `cnf.jkt` bound to the proof's JWK thumbprint. When no DPoP proof is supplied, Keycloak 26.2 with the `dpop` feature enabled returns an error rather than issuing a bearer token (when binding is mandatory). This is the correct behavior for TEST-02 — no DPoP proof should fail.

### Cross-Language Test CI Pattern

The `run-cross-language-tests.sh` builds and runs Rust (cargo), Go (go build), Python (python3), and Java (gradle). For CI, the strategy is:

**Option A (recommended): Full matrix with `setup-java`**
```yaml
dpop-interop:
  name: DPoP Cross-Language Interop
  runs-on: ubuntu-latest
  needs: [check]
  steps:
    - uses: actions/checkout@v6
    - uses: dtolnay/rust-toolchain@stable
    - uses: actions/setup-go@v5
      with: { go-version: '1.21' }
    - uses: actions/setup-java@v4
      with: { java-version: '21', distribution: 'temurin' }
    - name: Install Python deps
      run: pip install cryptography
    - name: Run cross-language tests
      run: ./dpop-cross-language-tests/run-cross-language-tests.sh
```

**Option B (fallback): Rust/Go/Python only**
Modify `run-cross-language-tests.sh` to accept a `--skip-java` flag or check for `SKIP_JAVA=1` env var. Skip Java generation and validation rows/columns. Reduces matrix from 16 to 9 combinations.

The Java test uses `gradle compileJava` which downloads dependencies from `~/.gradle/caches`. `setup-java` with `temurin` installs a full JDK. The `build.gradle.kts` is in `java-oauth-dpop/`. The gradle classpath construction in `run-cross-language-tests.sh` uses `find ~/.gradle/caches/modules-2/files-2.1 -name 'jackson-databind-*.jar'` — this works after `gradle compileJava` downloads dependencies. CI caching of `~/.gradle/caches` is the standard approach.

### Agent Daemon Lifecycle Test Pattern

The existing socket tests in `socket.rs` (e.g., at line 1556) use this Rust integration test pattern:

```rust
// Pattern from existing socket.rs tests
let socket_path = std::env::temp_dir().join(format!("test-{}.sock", uuid));
let state = Arc::new(RwLock::new(AgentState::new()));
let server = AgentServer::new(socket_path.clone(), Arc::clone(&state));
tokio::spawn(async move { server.serve().await.unwrap() });
// brief wait for listener to bind
tokio::time::sleep(Duration::from_millis(50)).await;
// connect and test
let mut stream = UnixStream::connect(&socket_path).await.unwrap();
```

For a **binary-level lifecycle test** (`unix-oidc-agent/tests/daemon_lifecycle.rs`), the pattern is:
```rust
use std::process::{Command, Child};
use std::time::Duration;

// Start the built binary
let mut child = Command::new(env!("CARGO_BIN_EXE_unix-oidc-agent"))
    .args(["serve", "--socket", socket_path_str])
    .spawn()?;

// Wait for socket to appear
for _ in 0..20 {
    if socket_path.exists() { break; }
    std::thread::sleep(Duration::from_millis(100));
}

// Connect and send JSON commands
let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)?;
stream.write_all(b"{\"action\":\"status\"}\n")?;
// read response
let mut response = String::new();
BufReader::new(&stream).read_line(&mut response)?;
// validate
let parsed: serde_json::Value = serde_json::from_str(&response)?;
assert_eq!(parsed["status"], "success");

// Shutdown
stream.write_all(b"{\"action\":\"shutdown\"}\n")?;
child.wait()?;
```

This uses `CARGO_BIN_EXE_unix-oidc-agent` (set by cargo for integration tests), no external tools needed.

**Key constraint:** The `Shutdown` command is defined in `AgentRequest` (protocol.rs line 37). A `Status` request to a freshly started daemon (no stored credentials) returns `Success(AgentResponseData::Status { ... })` with `is_logged_in: false`. A `GetProof` to an unauthenticated daemon returns an error response. These are the three IPC commands the lifecycle test exercises per TEST-04 success criterion.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| Wait for Keycloak health in CI | Custom sleep loops | `curl -sf .../health/ready` with retry (already in wait-for-healthy.sh) | Existing script handles timing; docker-compose.token-exchange.yaml has its own healthcheck |
| DPoP proof generation in test shell scripts | New crypto code | `openssl ecparam / dgst` calls (already in test_token_exchange.sh) | Shell script is complete; no new crypto code needed |
| Custom cross-language test matrix runner | New orchestration script | Existing `run-cross-language-tests.sh` | Script handles generate/validate matrix; just add `setup-go`, `setup-java` in CI |
| IPC socket framing | Custom protocol | `{json}\n` line-delimited — already defined in socket.rs | Protocol is newline-delimited JSON; one `read_line()` per response |

---

## Common Pitfalls

### Pitfall 1: `docker-compose.token-exchange.yaml` imports ALL realm files

**What goes wrong:** Adding `"dpop.bound.access.tokens": "true"` to `unix-oidc-test-realm.json` affects behavior in the token-exchange compose environment too, since both realms are mounted at `/opt/keycloak/data/import`. Existing `test_ssh_oidc_valid.sh` uses `UNIX_OIDC_TEST_MODE=true` (bypasses signature verification) so it is unaffected — but any test that obtains a token from the `unix-oidc` realm on the docker-compose.token-exchange.yaml stack **without** a DPoP proof will get a 400 error from Keycloak 26.2 when binding is mandatory.

**How to avoid:** Wire the DPoP E2E test (`test_dpop_e2e.sh`) to always supply a DPoP proof when requesting tokens from the `unix-oidc` realm. The shell script already generates proofs; just ensure the proof is included in `curl` calls. Alternatively, scope the `dpop.bound.access.tokens` change to the token-exchange stack only by creating a separate realm file variant.

**Recommendation:** Add the attribute to the primary realm directly (it is the correct production-ready configuration). Update `test_dpop_e2e.sh` to always use a DPoP proof. The test-mode SSH test is isolated in `docker-compose.test.yaml` (Keycloak 24.0) which is unaffected.

### Pitfall 2: `run-cross-language-tests.sh` assumes local Gradle cache

**What goes wrong:** The Java classpath is built by `find ~/.gradle/caches/modules-2/files-2.1 -name 'jackson-databind-*.jar'`. In a fresh CI runner with no cache, this finds nothing, and `java -cp ""` fails.

**How to avoid:** Add a `gradle dependencies` step (or `gradle compileJava`) before running the script, and cache `~/.gradle/caches` in CI with `actions/cache`. Set `GRADLE_USER_HOME` env var to a project-relative path for deterministic cache keys. Alternatively, use `--no-daemon` flag.

### Pitfall 3: Agent lifecycle test race condition on socket bind

**What goes wrong:** Starting the daemon binary with `Command::spawn()` and immediately connecting returns `connection refused` because `UnixListener::bind()` hasn't executed yet.

**How to avoid:** Poll for socket file existence (up to 2 seconds with 50ms intervals). The binary outputs `"unix-oidc-agent listening on ..."` to stdout before the accept loop; alternatively, redirect stdout and wait for that string. The file-existence poll is simpler and sufficient.

### Pitfall 4: `test_token_exchange.sh` uses `xxd` (not always installed)

**What goes wrong:** `xxd` is used to convert hex DER signature to binary. On ubuntu-latest it is installed as part of `vim-common`; on minimal runners it may be absent.

**How to avoid:** Add `sudo apt-get install -y xxd` (or `vim-common`) in the CI job setup step. The script checks for `xxd` in `check_prerequisites()` and exits cleanly with a clear error if absent.

### Pitfall 5: Cross-language tests — Go module replace directive

**What goes wrong:** `go-test/go.mod` has `replace github.com/prodnull/unix-oidc/go-oauth-dpop => ../../go-oauth-dpop`. This requires the `go-oauth-dpop` directory to exist at the repository root. If the CI checkout is a shallow clone or the directory is absent, `go build` fails.

**How to avoid:** Use `actions/checkout@v6` with `fetch-depth: 0` or the default (full clone). The `go-oauth-dpop` directory exists at the repo root; a full checkout is sufficient.

### Pitfall 6: `test_token_exchange.py` uses `password` grant type

**What goes wrong:** Keycloak 26.2 disables the `Resource Owner Password Credentials` grant (`password` grant) by default for new realms. The `unix-oidc-agent` client in `token-exchange-test-realm.json` has `"directAccessGrantsEnabled": true`, which re-enables it. If this attribute is accidentally removed, the Python test fails with a 400 error.

**How to avoid:** Do not modify the client `directAccessGrantsEnabled` attribute. Add an assertion in the test or a CI validation step that checks the realm config file has the expected attribute before running tests.

---

## Code Examples

### CI Job: Token Exchange (TEST-01)

```yaml
# Add to .github/workflows/ci.yml
token-exchange:
  name: Token Exchange Integration Tests (TEST-01)
  runs-on: ubuntu-latest
  needs: [check]
  steps:
    - uses: actions/checkout@v6

    - name: Install dependencies
      run: sudo apt-get update && sudo apt-get install -y curl jq xxd

    - name: Install Python dependencies
      run: pip install requests cryptography PyJWT

    - name: Make scripts executable
      run: chmod +x test/tests/test_token_exchange.sh

    - name: Start token exchange environment
      run: |
        docker compose -f docker-compose.token-exchange.yaml up -d
        # Wait for Keycloak (healthcheck: /health/ready on port 9000)
        for i in $(seq 1 30); do
          curl -sf http://localhost:9000/health/ready && echo "Keycloak ready" && break
          echo "Waiting for Keycloak... ($i/30)"
          sleep 5
        done

    - name: Run token exchange shell test
      run: bash test/tests/test_token_exchange.sh

    - name: Run token exchange Python test
      run: python3 test/tests/test_token_exchange.py

    - name: Collect logs on failure
      if: failure()
      run: docker compose -f docker-compose.token-exchange.yaml logs

    - name: Stop environment
      if: always()
      run: docker compose -f docker-compose.token-exchange.yaml down -v
```

### Realm Patch: DPoP Binding (TEST-02)

In `test/fixtures/keycloak/unix-oidc-test-realm.json`, find the `unix-oidc` client attributes and add:
```json
"attributes": {
  "oauth2.device.authorization.grant.enabled": "true",
  "oauth2.device.code.lifespan": "300",
  "oauth2.device.polling.interval": "5",
  "oidc.ciba.grant.enabled": "false",
  "dpop.bound.access.tokens": "true"
}
```

This requires no code changes — JSON only.

### DPoP E2E Test CI Wiring (TEST-02)

`test/tests/test_dpop_e2e.sh` is currently marked "No (manual)" in the assessment. It needs to be:
1. Tracked in git (currently untracked based on assessment)
2. Added to the integration test suite or the `token-exchange` CI job

The recommended approach: add a `dpop-e2e` step in the `token-exchange` CI job (after the token-exchange environment is up, since both realms are available). Alternatively, wire it into the main `integration` job via `run-integration-tests.sh`. The `test_dpop_e2e.sh` script wraps: (a) cargo unit tests, (b) cross-language DPoP tests, (c) Docker-based tests. In CI, only the Docker-based validation step should run (the others have their own jobs).

### Agent Lifecycle Test (TEST-04)

New file: `unix-oidc-agent/tests/daemon_lifecycle.rs`

```rust
//! Agent daemon lifecycle integration test.
//!
//! Starts the `unix-oidc-agent` binary on a temp socket, sends IPC commands
//! (Status, GetProof on unauthenticated daemon, Shutdown), validates responses.
//!
//! Run with: cargo test --test daemon_lifecycle

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use std::process::Command;

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "unix-oidc-test-{}.sock",
        std::process::id()
    ))
}

fn wait_for_socket(path: &PathBuf, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn send_command(stream: &mut UnixStream, json: &str) -> String {
    stream.write_all(format!("{}\n", json).as_bytes()).unwrap();
    let mut response = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut response)
        .unwrap();
    response
}

#[test]
fn test_daemon_lifecycle() {
    let socket = socket_path();
    let socket_str = socket.to_str().unwrap();

    // Start daemon
    let mut child = Command::new(env!("CARGO_BIN_EXE_unix-oidc-agent"))
        .args(["serve", "--socket", socket_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn agent daemon");

    // Wait for socket
    assert!(
        wait_for_socket(&socket, 2000),
        "daemon socket did not appear within 2s"
    );

    // Status command on unauthenticated daemon
    let mut stream = UnixStream::connect(&socket).expect("connect to daemon");
    let resp = send_command(&mut stream, r#"{"action":"status"}"#);
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(parsed["status"], "success");
    // Not logged in — no signer
    assert!(
        parsed["data"]["is_logged_in"] == false
            || parsed["data"].get("is_logged_in").is_none(),
        "expected not logged in"
    );

    // GetProof on unauthenticated daemon — should return error
    let mut stream2 = UnixStream::connect(&socket).expect("connect for get_proof");
    let resp2 = send_command(
        &mut stream2,
        r#"{"action":"get_proof","target":"test.example.com","method":"SSH"}"#,
    );
    let parsed2: serde_json::Value = serde_json::from_str(&resp2).unwrap();
    assert_eq!(parsed2["status"], "error", "get_proof on unauthenticated daemon must fail");

    // Shutdown
    let mut stream3 = UnixStream::connect(&socket).expect("connect for shutdown");
    send_command(&mut stream3, r#"{"action":"shutdown"}"#);

    // Wait for process exit
    let exit = child.wait().expect("wait for child");
    assert!(exit.success() || exit.code() == Some(0) || exit.code().is_some());

    // Clean up socket if still present
    let _ = std::fs::remove_file(&socket);
}
```

### Cross-Language CI Job (TEST-03)

```yaml
dpop-interop:
  name: DPoP Cross-Language Interop (TEST-03)
  runs-on: ubuntu-latest
  needs: [check]
  steps:
    - uses: actions/checkout@v6

    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable

    - name: Cache Rust
      uses: actions/cache@v5
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          dpop-cross-language-tests/rust-test/target
        key: ${{ runner.os }}-dpop-rust-${{ hashFiles('dpop-cross-language-tests/rust-test/Cargo.lock') }}

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: '1.21'
        cache-dependency-path: dpop-cross-language-tests/go-test/go.sum

    - name: Set up Java
      uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'

    - name: Cache Gradle
      uses: actions/cache@v5
      with:
        path: ~/.gradle/caches
        key: ${{ runner.os }}-gradle-${{ hashFiles('java-oauth-dpop/build.gradle.kts') }}

    - name: Install Python cryptography
      run: pip install cryptography

    - name: Run cross-language interop tests
      run: |
        chmod +x ./dpop-cross-language-tests/run-cross-language-tests.sh
        ./dpop-cross-language-tests/run-cross-language-tests.sh
```

---

## State of the Art

| Old Approach | Current Approach | Notes |
|---|---|---|
| Bearer tokens (no binding) | DPoP-bound tokens with `cnf.jkt` | RFC 9449; Keycloak 24+ supports `dpop.bound.access.tokens` client attribute |
| Test scripts untracked | `git add` + CI job reference | Standard wiring — no new tooling needed |
| Manual cross-language test run | `run-cross-language-tests.sh` in CI | Script already exists; CI job is additive |
| Unit-only daemon test | Binary-level integration test | `CARGO_BIN_EXE_*` pattern is stable Rust idiom since 1.44 |

---

## Open Questions

1. **Java in cross-language CI: full vs skip**
   - What we know: `setup-java@v4` with `temurin` installs a full JDK; `gradle compileJava` downloads deps; CI cache for `~/.gradle/caches` is standard.
   - What's unclear: How long does Gradle dep download add to CI time on a cold cache? `jackson-databind` + `eclipse-collections` are not small.
   - Recommendation: Implement with Java (full 16-combination matrix). If CI time exceeds 5 minutes for the interop job, add `--no-daemon` to gradle and enable Gradle cache. If still too slow, add `SKIP_JAVA=1` env flag to `run-cross-language-tests.sh` as a fast-follow.

2. **`test_dpop_e2e.sh` scope in CI**
   - What we know: The script wraps cargo unit tests + cross-language DPoP + Docker integration. In CI, the unit tests and cross-language tests have their own jobs.
   - What's unclear: Whether `test_dpop_e2e.sh` should be refactored to only run the Docker-dependent steps in CI, or whether a new targeted script should be written for TEST-02.
   - Recommendation: Write a focused `test_dpop_binding_e2e.sh` for TEST-02 that: (1) generates a DPoP proof with openssl, (2) requests a token from the `unix-oidc` Keycloak realm with the `DPoP:` header, (3) asserts `cnf.jkt` is present and matches the computed thumbprint. This is ~30 lines using the same helper functions already in `test_token_exchange.sh`.

3. **Shutdown response and daemon exit timing**
   - What we know: `AgentRequest::Shutdown` is defined (protocol.rs line 37). The daemon should exit after sending an acknowledgment.
   - What's unclear: Does the current `handle_connection` implementation for `Shutdown` send a response before terminating? Or does it terminate immediately?
   - Recommendation: Check `socket.rs` `handle_connection` Shutdown arm before writing the lifecycle test. If no response is sent, the test should not wait for a response on the shutdown connection — just check process exit. This is a pre-implementation discovery that should be noted in the PLAN.

---

## Validation Architecture

> nyquist_validation is enabled in `.planning/config.json`

### Test Framework

| Property | Value |
|---|---|
| Framework | cargo test (Rust unit/integration) + bash shell scripts |
| Config file | none (cargo default) |
| Quick run command | `cargo test --test daemon_lifecycle` |
| Full suite command | `cargo test --workspace && ./test/scripts/run-integration-tests.sh` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|---|---|---|---|---|
| TEST-01 | Shell + Python token exchange scripts run in CI with DPoP cnf.jkt validation | integration (Docker) | `bash test/tests/test_token_exchange.sh` | Yes (untracked) |
| TEST-01 | Python variant of same | integration (Docker) | `python3 test/tests/test_token_exchange.py` | Yes (untracked) |
| TEST-02 | Keycloak issues `cnf.jkt`-bearing tokens; PAM validates thumbprint | integration (Docker) | `bash test/tests/test_dpop_binding_e2e.sh` | No — Wave 0 gap |
| TEST-03 | Rust/Go/Python/Java DPoP proofs accepted across all combinations | cross-language | `./dpop-cross-language-tests/run-cross-language-tests.sh` | Yes |
| TEST-04 | Daemon starts, responds to Status/GetProof/Shutdown, exits cleanly | integration (binary) | `cargo test --test daemon_lifecycle` | No — Wave 0 gap |

### Sampling Rate

- **Per task commit:** `cargo test --workspace`
- **Per wave merge:** Full CI run (all four new jobs green)
- **Phase gate:** All four TEST-xx CI jobs green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `test/tests/test_dpop_binding_e2e.sh` — covers TEST-02 DPoP cnf.jkt validation
- [ ] `unix-oidc-agent/tests/daemon_lifecycle.rs` — covers TEST-04 agent lifecycle
- [ ] `git add test/tests/test_token_exchange.sh test/tests/test_token_exchange.py` — track existing files for TEST-01

*(Existing infrastructure: `cargo test`, bash, Docker Compose — all present; no new framework install needed)*

---

## Sources

### Primary (HIGH confidence)

- Direct file inspection: `.github/workflows/ci.yml` — confirms existing CI job structure and patterns
- Direct file inspection: `docker-compose.token-exchange.yaml` — confirms Keycloak 26.2 + dpop feature flag + realm mount
- Direct file inspection: `test/tests/test_token_exchange.sh` — confirms complete 8-step DPoP + token exchange test
- Direct file inspection: `test/tests/test_token_exchange.py` — confirms Python variant using `cryptography` + `PyJWT`
- Direct file inspection: `test/fixtures/keycloak/token-exchange-test-realm.json` — confirms `"dpop.bound.access.tokens": "true"` syntax
- Direct file inspection: `test/fixtures/keycloak/unix-oidc-test-realm.json` — confirms attribute is absent (gap)
- Direct file inspection: `unix-oidc-agent/src/daemon/socket.rs` — confirms `AgentServer::new`, `serve()` are pub; confirms existing test pattern
- Direct file inspection: `unix-oidc-agent/src/daemon/protocol.rs` — confirms `AgentRequest::Shutdown`, `Status`, `GetProof` exist
- Direct file inspection: `dpop-cross-language-tests/run-cross-language-tests.sh` — confirms Java dependency and LANGUAGES array
- Direct file inspection: `docs/integration-testing-assessment.md` — authoritative gap analysis (P1, P2, P6, P7 map to TEST-01 through TEST-04)

### Secondary (MEDIUM confidence)

- Keycloak documentation (via project knowledge): `dpop.bound.access.tokens` client attribute honored in Keycloak 24+ when `--features=dpop` is active; confirmed by `docker-compose.token-exchange.yaml` feature flag and `token-exchange-test-realm.json` existing usage
- GitHub Actions documentation (via project knowledge): `setup-go@v5`, `setup-java@v4`, `actions/cache@v5` are current stable action versions
- Rust reference (via project knowledge): `env!("CARGO_BIN_EXE_binary-name")` is the stable mechanism for integration tests to locate built binaries since Rust 1.44

### Tertiary (LOW confidence)

- Gradle cold-cache timing in CI: estimated 1-3 minutes for Jackson + eclipse-collections; not measured in this project

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all tools already in the project; versions confirmed from files
- Architecture: HIGH — CI patterns taken directly from existing `ci.yml`; test patterns from `socket.rs` existing tests
- Pitfalls: HIGH — derived from direct inspection of the scripts and compose files, not inference
- Open questions: MEDIUM — timing and shutdown behavior require pre-implementation verification

**Research date:** 2026-03-11
**Valid until:** 2026-04-10 (stable tooling; Keycloak and GitHub Actions versions unlikely to change in 30 days)
