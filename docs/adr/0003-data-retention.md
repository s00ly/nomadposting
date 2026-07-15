# ADR 0003: Data Minimization and Retention

- Status: Accepted
- Date: 2026-07-14

## Context

The application must retain enough state to queue a post, prevent blind duplicates, reconcile an ambiguous X response, and report partial cross-platform completion. Retaining content, credentials, IP addresses, raw protocol messages, or long histories creates a second privacy risk that does not improve publication correctness.

Deletion on SSDs, journaling filesystems, snapshots, and provider-managed storage cannot be proven byte-for-byte. Retention policy must therefore combine minimization, encryption, short lifetimes, backup exclusion, and cryptographic erasure where practical.

## Decision

### Content

- Encrypt drafts, approved content, and unresolved job payloads at rest with a key protected by the operating system or TPM.
- Use per-record envelope encryption so successful content keys can be destroyed without rotating every retained record. Seal the wrapping key to the TPM or host secret store.
- Retain content only while a job is queued, partial, or unknown and the payload is required for safe reconciliation.
- Delete local content after both platforms reach a resolved state.
- Do not retain a convenience archive of published content. The public platform identifiers are sufficient for later lookup.

### Operational metadata

- Retain encrypted operational metadata for seven days after resolution.
- Allowed fields are job ID, approval hash, selected exit country, normalized state transitions, normalized error code, Nostr event ID, X post ID, acknowledgement count, component version, and bounded duration.
- After seven days, delete the metadata and retire the period key where key separation permits cryptographic erasure.
- Retain aggregated endpoint-health metrics for at most 90 days. Aggregates must not contain job IDs, content, account identifiers, exact IPs, per-post country sequences, or per-post timestamps.

### Data never persisted in logs or job history

- X access tokens, refresh tokens, authorization codes, PKCE verifiers, passwords, cookies, and Authorization headers.
- Nostr private keys, NIP-46 connection secrets, signer request payloads, and raw signed events.
- VPN private keys, provider credentials, provider account IDs, and raw configuration.
- Draft or published content, links, media, raw HTTP bodies, and raw relay notices.
- Home IP, exact exit IP, VPN endpoint IP, raw DNS results, packet payloads, and future country selections.

### Backups and diagnostics

- Exclude secret stores, drafts, raw job databases, packet captures, and VPN configurations from routine backups.
- A recovery backup requires a documented owner, purpose, encryption key, expiry, restore test, and deletion test.
- Production debug mode does not permit raw request, response, token, content, or network logging.
- Disable core dumps for secret-bearing processes.
- Packet captures used for adversarial testing must use test accounts and canary data, remain access-controlled, and be deleted after evidence review.

### Exceptions

- A job in `PARTIAL` or `UNKNOWN` may retain its encrypted payload beyond seven days only while manual reconciliation is active.
- The UI must show the retained item and allow the operator to abandon it, which deletes the payload and records only a normalized abandonment state.
- Legal or incident preservation is not automatic. It requires an explicit local administrative action, documented scope and expiry, and must never include credentials that can be revoked instead.

## Consequences

Positive:

- A log or database disclosure contains less useful content and network metadata.
- Short retention reduces long-term behavioral profiling on the host.
- De-identified 90-day health aggregates support capacity planning without preserving a posting history.
- Unknown X outcomes can still be reconciled without blind retries.
- The policy has concrete fields and timers that can be tested.

Costs and residual risks:

- The local application cannot provide a permanent post archive.
- Deleted data may remain in filesystem journals, SSD remapping, snapshots, or provider backups.
- Platform copies and Nostr relay copies are outside local deletion control.
- A host administrator can inspect data while it is legitimately in use.
- Holding partial or unknown jobs extends exposure until the operator resolves or abandons them.

## Rejected alternatives

- No persistent state: rejected because crash recovery could lose platform IDs or create duplicates.
- Full request and response logs: rejected because they expose content, credentials, and identifiers.
- Store exact exit IP for proof: rejected because it increases linkability and still does not prove physical server location.
- Indefinite encrypted history: rejected because encryption does not remove access-control, key-compromise, or profiling risk.
- Claim secure byte erasure on SSD: rejected because the application cannot verify it.

## Verification

- Retention tests advance the clock and prove resolved content is deleted immediately and operational metadata is deleted after seven days.
- Retention tests prove health aggregates contain no prohibited dimensions and expire after 90 days.
- Unknown and partial jobs retain only the encrypted minimum required for reconciliation.
- Seeded canary scans cover logs, journals, database pages, temporary files, argv, environment, crash artifacts, and backups.
- Backup manifests reject prohibited paths and a restore test does not recreate revoked credentials or deleted content.
- Logging-schema tests fail when an unapproved field or raw remote error is emitted.
- Abandoning an unresolved job deletes its encrypted payload and prevents retry.

## Revisit when

Revisit this ADR before adding media, analytics, cloud synchronization, multi-device operation, administrator dashboards, legal-hold workflows, or any retention period longer than seven days.
