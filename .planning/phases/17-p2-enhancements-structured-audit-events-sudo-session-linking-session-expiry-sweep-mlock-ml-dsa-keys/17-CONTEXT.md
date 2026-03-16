# Phase 17: P2 Enhancements — Context

**Gathered:** 2026-03-13
**Status:** Ready for planning
**Source:** NEXT-SESSION-PLAN.md + v2.0-MILESTONE-AUDIT.md

<domain>
## Phase Boundary

This phase delivers four targeted enhancements that harden the agent daemon's observability, session hygiene, and PQC readiness:

1. **Agent-side structured audit events (OBS-1)** — Emit machine-parseable audit events from the agent daemon for authentication, token refresh, session lifecycle, and step-up operations
2. **Sudo session linking (OBS-3)** — Link sudo step-up session IDs to the parent SSH session for end-to-end audit correlation
3. **Session expiry sweep** — Background task that reaps orphaned session records (e.g., from crashed sshd workers that never sent SessionClosed)
4. **mlock ML-DSA key material** — Extend ProtectedSigningKey's mlock pattern to ML-DSA-65 keys before promoting PQC from experimental

</domain>

<decisions>
## Implementation Decisions

### Structured Audit Events
- Use tracing structured events with a dedicated `audit` target (filterable via tracing-subscriber)
- Events must include: event_type, timestamp, session_id, username, outcome, and event-specific fields
- JSON-serializable for SIEM ingestion (already have JSON tracing from Phase 13)
- Audit events are INFO level minimum — never filtered by default log level

### Sudo Session Linking
- Parent SSH session_id must be propagated to sudo step-up IPC messages
- The CIBA poll result should carry the parent session_id for correlation
- Audit events for step-up must include both sudo_session_id and parent_session_id

### Session Expiry Sweep
- Periodic background task in the agent daemon (Tokio interval)
- Scan /run/unix-oidc/sessions/ for expired session files (check token_exp from session record)
- Configurable sweep interval (default: 5 minutes)
- Must handle partial/corrupt session files gracefully (warn + remove)
- Must not race with active session close operations (file lock or atomic check)

### mlock ML-DSA Keys
- ML-DSA-65 key material must be mlock'd like EC keys in ProtectedSigningKey
- The HybridPqcSigner holds both EC and ML-DSA keys — both must be protected
- Best-effort mlock (warn on failure, same as EC path)
- Zeroize on drop must be verified for ML-DSA key types

### Claude's Discretion
- Internal implementation details of sweep scheduling
- Audit event field naming conventions (follow existing tracing patterns)
- Whether sweep uses inotify/kqueue or simple polling

</decisions>

<specifics>
## Specific Ideas

- Audit events should follow the pattern established in Phase 13's operational hardening (tracing spans, structured fields)
- Session sweep should respect the same session directory layout from Phase 9 (SES-04)
- ML-DSA key protection should mirror the ProtectedSigningKey pattern from Phase 1 (MEM-04, MEM-05)
- The v2.0 milestone audit identified session close IPC as previously broken (fixed in Phase 14) — sweep is the safety net for edge cases

</specifics>

<deferred>
## Deferred Ideas

- Audit event forwarding to external SIEM (future ops milestone)
- inotify-based session file watching (polling is sufficient for MVP)

</deferred>

---

*Phase: 17-p2-enhancements*
*Context gathered: 2026-03-13 from session plan*
