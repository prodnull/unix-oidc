# Phase 27: Multi-IdP Advanced + Observability - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Add IdP priority ordering, health monitoring with automatic quarantine/recovery, and config hot-reload to the multi-issuer auth pipeline. Extend structured audit events to cover no-token attempts, key lifecycle, IPC session-close failures, OCSF schema fields, log retention guidance, and GDPR erasure documentation. Ten requirements: MIDP-09, MIDP-10, MIDP-11, OBS-02, OBS-04, OBS-05, OBS-06, OBS-07, OBS-08, OBS-09.

</domain>

<decisions>
## Implementation Decisions

### IdP Priority Ordering (MIDP-09)
- **Token-driven routing with priority fallback.** Current flow extracts `iss` from token → `issuer_by_url()` lookup. Priority ordering matters only when the token's issuer matches no configured issuer or when routing needs a default. The `issuers[]` array order in config IS the priority — first match wins.
- **Structured log on issuer selection.** Emit an INFO-level audit event showing which issuer was selected and its position in the priority list, enabling operators to observe selection order.
- **No behavioral change for exact-match routing.** When a token's `iss` claim matches exactly one configured issuer, priority is irrelevant — the match is used. Priority only governs fallback/default behavior.

### IdP Health Monitoring (MIDP-10)
- **Per-process health state with file-based persistence.** Each forked sshd process is ephemeral — no shared in-memory state. Health state (degraded flag, failure count, last-failure timestamp) persisted to `/run/unix-oidc/issuer-health/{issuer-hash}.json` with atomic write (write-to-tmp + rename).
- **Degradation threshold: 3 consecutive JWKS fetch failures.** After 3 failures, the issuer is marked degraded and skipped for subsequent auth attempts. A configurable `recovery_interval_secs` (default 300s) determines when to retry.
- **Recovery: successful JWKS fetch clears degraded state.** When a retry succeeds, the health file is updated to clear the degraded flag and reset the failure counter.
- **Structured audit event on state transitions.** Emit `ISSUER_DEGRADED` and `ISSUER_RECOVERED` audit events for SIEM visibility.

### Config Hot-Reload (MIDP-11)
- **Stat-based freshness check per auth attempt.** On each `pam_sm_authenticate` call, stat `policy.yaml` and compare mtime to a cached value. If changed, re-parse config. This works naturally in the forked-sshd model — each fork gets fresh state.
- **No SIGHUP handler.** PAM modules run in sshd's process space — sending SIGHUP to sshd restarts it (undesirable). The stat-based approach is simpler, more correct, and doesn't require signal handling.
- **Atomic config reload.** If re-parse fails (bad YAML, validation error), keep the old config and log a WARNING. Never let a bad config file deny all authentication.
- **Structured log on reload.** Emit INFO when config is reloaded, WARNING when reload fails with reason.

### No-Token Audit Events (OBS-02)
- **New `auth_no_token` event type.** When PAM receives an auth attempt with no token (empty or missing), emit a structured audit event with `event_type=auth_no_token`, username, source IP, and timestamp. Distinguishable from token validation failures in SIEM queries.
- **Emit before returning PAM_AUTH_ERR.** The event should be logged even if the PAM module returns early.

### Key Lifecycle Audit Events (OBS-04)
- **Three new event types in the agent daemon:** `KEY_GENERATED`, `KEY_LOADED`, `KEY_DESTROYED`. Each carries key type (DPoP/PQC), key ID (thumbprint prefix), and timestamp.
- **Emit at the actual lifecycle points** — not just tracing spans. These are structured audit events (target: `unix_oidc_audit`) for SIEM ingestion.

### Log Retention & Logrotate (OBS-05)
- **Ship a logrotate config snippet** at `deploy/logrotate.d/unix-oidc`. Rotate `/var/log/unix-oidc/*.log` weekly, keep 52 weeks (1 year), compress after 1 rotation.
- **Document log retention considerations** in `docs/log-retention.md` — compliance periods (SOC2: 1 year, PCI-DSS: 1 year, HIPAA: 6 years), syslog vs file logging, integration with centralized logging (Splunk, ELK, Datadog).

### Audit Log Tamper-Evidence (OBS-06)
- **HMAC chain for audit events.** Each audit event includes an HMAC of the previous event's hash + current event payload, creating a verifiable chain. If any event is deleted or modified, the chain breaks.
- **HMAC key from environment variable** `UNIX_OIDC_AUDIT_HMAC_KEY`. If unset, tamper-evidence is disabled with a WARNING at startup.
- **Chain verification utility.** Ship a `unix-oidc-audit-verify` subcommand that reads a log file and verifies the chain, reporting the first break point.

### OCSF Schema Fields (OBS-07)
- **Add OCSF fields to all audit events:** `category_uid` (3 = Identity & Access), `class_uid` (3002 = Authentication), `severity_id` (mapped from AuditSeverity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical), `activity_id` (1=Logon, 2=Logoff, etc.), `type_uid` (class_uid * 100 + activity_id).
- **OCSF version field:** Include `metadata.version: "1.3.0"` to indicate which OCSF schema version is used.
- **Backward compatible.** Existing JSON fields remain; OCSF fields are additive. No existing SIEM integration breaks.

### IPC Session-Close Failure Audit (OBS-08)
- **New `SESSION_CLOSE_FAILED` event type.** When `pam_sm_close_session` fails to send SessionClosed IPC (timeout, connection refused, etc.), emit a structured audit event with session ID, username, error reason.
- **Best-effort, not blocking.** The audit event is emitted on failure, but `pam_sm_close_session` still returns PAM_SUCCESS — failing to close a session shouldn't lock the user out.

### GDPR Article 17 Erasure (OBS-09)
- **Documentation only.** Ship `docs/gdpr-erasure-guide.md` with:
  - What data unix-oidc stores (tokens, DPoP keys, session records, audit logs)
  - Where each data type lives (memory, keyring, files, syslog)
  - How to erase each type (secure_delete for files, keyring deletion, log rotation)
  - What cannot be erased (syslog entries shipped to external SIEM)
  - Implementation guidance for data controllers

### Claude's Discretion
- HMAC algorithm choice (SHA-256 is the obvious choice)
- Exact OCSF field values for each event type
- Health file format details
- Log retention periods in the logrotate snippet
- Test organization and naming
- Order of implementation across plans

</decisions>

<specifics>
## Specific Ideas

- User's guiding principle: **security first, most flexible within those parameters, maximum visibility through logs and events**
- The forked-sshd model is the key architectural constraint — no shared in-memory state between auth attempts, so health monitoring and config reload must use file-based persistence
- HMAC chain is the strongest tamper-evidence mechanism that doesn't require external infrastructure (no database, no blockchain)
- OCSF schema alignment enables "plug and play" SIEM ingestion — operators shouldn't need custom field mapping
- OBS-05 and OBS-09 are documentation-only requirements — no code changes

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AuditEvent` enum (audit.rs): Extend with new variants for `auth_no_token`, `KEY_GENERATED`, `KEY_LOADED`, `KEY_DESTROYED`, `SESSION_CLOSE_FAILED`, `ISSUER_DEGRADED`, `ISSUER_RECOVERED`
- `AuditEvent::log()` (audit.rs:414): Already handles syslog + structured JSON output
- `syslog_severity()` (audit.rs:451): Extend for new event types
- `extract_iss_for_routing()` (auth.rs:74): Entry point for issuer selection — add priority logging here
- `pam_sm_close_session` (lib.rs): Add audit event on IPC failure
- `PolicyConfig::load_from()` (config.rs): Basis for hot-reload — add stat-check wrapper

### Established Patterns
- `target: "unix_oidc_audit"` for structured audit events (Phase 17)
- `AuditSeverity` enum for syslog mapping (Phase 24)
- Per-issuer config fields on `IssuerConfig` (Phase 21/25/26)
- File-based session records at `/run/unix-oidc/sessions/` (Phase 9) — similar pattern for health files
- Atomic file write (write-to-tmp + rename) used in session records

### Integration Points
- `pam_sm_authenticate` (lib.rs:~120): Add no-token audit event, config freshness check
- `authenticate_multi_issuer` (auth.rs:~100): Add issuer priority logging, health check before JWKS fetch
- `JwksProvider::get_key()` (jwks.rs): Wrap with health tracking (increment failure on error, clear on success)
- Agent daemon key operations: `ProtectedSigningKey::new()`, `from_key()`, `drop()` — add lifecycle audit events
- `cleanup_session()` (socket.rs): Add failure audit event

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 27-multi-idp-advanced-observability*
*Context gathered: 2026-03-16*
