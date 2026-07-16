# Security Requirements and Operating Policy

This document defines the minimum security posture for NomadPosting. It is normative for implementation and release. These are requirements, not evidence that a deployment satisfies them. The fuller threat analysis is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Supported use

NomadPosting supports one operator publishing approved content to one X account through a dedicated France exit and one Nostr identity through rotating, allowlisted VPN countries. It is a source-IP privacy tool, not an anonymity system or an enforcement-evasion tool.

The implementation must not support account fleets, third-party accounts, platform limit circumvention, browser automation of X, session-cookie reuse, misleading location claims, or silent network fallback.

## Supported versions and official scope

| Version | Security support | Live status |
|---|---|---|
| `main` | Accepted for private vulnerability reports | Dry-run research preview only |
| Tagged releases | None exist | Unsupported |
| Forks and third-party deployments | Controlled by their operators | Not official or certified by this project |

This policy governs the `s00ly/nomadposting` repository and artifacts explicitly
published from it. It does not add a restriction to the AGPL or certify a fork.
The [name and provenance policy](../BRAND_POLICY.md) describes accurate use of
project identity.

No live deployment is supported. A report showing that a missing live feature
is missing is not a vulnerability unless dry-run behavior creates a separate
security impact. Reports that challenge a release assumption are welcome when
they follow the research boundaries below.

## Vulnerability reporting and research boundaries

Use [GitHub Private Vulnerability Reporting](https://github.com/s00ly/nomadposting/security/advisories/new)
for exploitable details. Public issues are appropriate only for
non-exploitable design questions, threat-model hypotheses, and hardening
proposals.

This project can authorize research only against its own code and
maintainer-controlled disposable environments. It does not authorize testing
against X, Nostr relays, VPN providers, cloud providers, accounts, networks, or
other third-party systems. Obtain separate permission from each owner.

When testing this project:

- use synthetic data, disposable keys, local fixtures, and test accounts you
  own;
- do not access another person's data, credentials, account, or traffic;
- do not use denial of service, social engineering, persistence, credential
  harvesting, or automated scanning of public infrastructure;
- stop when a test could affect availability, disclose data, or leave the
  disposable environment;
- retain only the minimum sanitized evidence needed to reproduce the issue and
  delete sensitive research artifacts after coordination.

There is no bug bounty, guaranteed safe harbor, or response-time SLA. The
maintainer targets acknowledgement within seven calendar days and an initial
severity assessment within fourteen. These are best-effort targets. Reporter
credit is offered only with the reporter's consent.

For security-sensitive fixes, use a GitHub draft advisory and its private fork.
Do not open a public issue or pull request containing exploit details before
coordinated disclosure. The maintainer decides whether an advisory or CVE is
appropriate based on affected users and release state. Under the AGPL, source
for a modified network-served fix must be available to remote users no later
than deployment of that fix. Corresponding source never includes production
credentials or private operational configuration.

## Mandatory architecture

- Linux is the security baseline for the first release.
- The controller and posting worker run unprivileged.
- A minimal broker holds only the network privileges needed to create and destroy the per-post namespace and WireGuard interface.
- The broker accepts only validated `job_id`, `platform`, and registered `endpoint_id` values over a root-owned Unix socket. It independently enforces the compiled platform capability and exact dedicated X endpoint. It accepts no command, path, route, arbitrary address, or shell fragment.
- Each platform attempt gets a fresh namespace containing only loopback and one WireGuard interface.
- nftables policy is drop-by-default. No host or physical-interface route is available to the worker.
- The worker has a private resolver configuration that uses only a resolver through the tunnel.
- IPv6 is tunneled or disabled inside the namespace.
- X server-side OAuth token exchange, refresh, publication, and reconciliation use only the registered dedicated France endpoint. The user-agent authorization page follows the browser's route and is outside the posting worker.
- NIP-46 signing, Nostr relay requests, and Nostr country verification use one separately selected and pinned Nostr endpoint.
- X and Nostr execute in separate namespaces and have independent receipts and terminal states.
- Workers run as non-root UIDs with read-only filesystems, per-attempt tmpfs, and no capability beyond the minimum required by the fixed launcher. The broker destroys the namespace, interface, tmpfs, and credential handles after every outcome.
- Tunnel or verification failure stops the job. There is no direct-network fallback.
- The publishing path contains no browser, WebView, or WebRTC stack.

## Egress policy

### Nostr rotation

- The country pool is an explicit allowlist of provider, country, and exit tuples.
- Countries prohibited by the operator's applicable law or provider/platform terms must not enter the pool.
- Selection occurs at dispatch using an operating-system CSPRNG and unbiased sampling.
- Select uniformly by healthy country, excluding the immediately previous country, then select an exit within that country.
- Require at least three healthy approved countries. If no different healthy country exists, return a visible failure and leave the Nostr destination queued.
- Do not precompute or log future selections.
- GeoIP can identify disagreement, not prove physical server location. UI and logs must call the value an exit country, never the user's location.
- Pin the selected endpoint across signing, every relay attempt, and retry for the event.

### X stable exit

- Pin production X traffic to one registered static France endpoint.
- Keep `rotating_country` disabled in production policy.
- Never change the X endpoint after a 403, 429, challenge, restriction, exhausted credit response, or ambiguous result.
- Enabling X rotation requires a test-account pilot plus written X clarification or a new explicit risk decision and ADR.
- All request builders omit X geotags and Nostr location tags. A future user-supplied location feature requires separate review and explicit consent.

## Authentication and secrets

### Nostr

- Prefer NIP-46. The main application must not receive or store the user's private key.
- Pin the expected signer public key and validate the NIP-46 connection secret.
- Request `sign_event:1` only. Add `sign_event:22242` only when a configured relay requires NIP-42 authentication.
- The signer must enforce permissions and reject unexpected event kinds.
- Never fall back from NIP-46 to a locally stored private key.
- If local-key support is ever proposed, it requires a new threat-model review and ADR before implementation.

### X

- Use the official X API and OAuth 2.0 Authorization Code with PKCE.
- Validate `state`, use an exact redirect URI, and use a cryptographically random verifier.
- Request only `tweet.write`, `tweet.read`, and `users.read`; request `offline.access` only for approved unattended scheduling.
- Never request or store the X password, session cookies, or a user's developer secrets.
- Refresh and revoke tokens through the dedicated X France endpoint.
- Bind credentials to the single configured X user ID and reject a mismatched account response.

### VPN and local secret storage

- VPN private keys and provider credentials are root-readable only and unavailable to the worker.
- Prefer distinct keys per provider or exit when the provider supports them.
- Encrypt persistent OAuth and pairing material with an OS or TPM-backed key.
- Deliver short-lived credentials through a sealed memory handle or pipe, not command-line arguments, environment variables, or temporary files.
- Disable core dumps for secret-bearing processes. Do not enable swap of secret memory where the runtime can safely prevent it.
- Zeroization is best effort in managed runtimes and must not be presented as proof that memory cannot be recovered.
- Secrets, real account IDs, and production VPN configurations must never be committed to the repository or included in fixtures.
- Provide tested rotation and revocation procedures before production use.

## Approval and posting integrity

- Authentication is not publishing consent.
- Before queueing, show the exact content, X and Nostr destinations, and whether any geotag will be attached.
- Bind approval to a hash of content, target set, media set, and geotag state. Any change invalidates approval.
- Use an explicit durable state machine: `DRAFT`, `APPROVED`, `ROUTING`, `PUBLISHING`, `COMPLETE`, `PARTIAL`, `UNKNOWN`, or `FAILED`.
- The X and Nostr payload hashes are bound to one approval, but each platform executes in its own namespace and resolves independently.
- One signed Nostr event ID and one pinned Nostr egress lease are reused for all configured relay submissions.
- Validate Nostr event serialization, event ID, public key, and signature before relay submission.
- Require the configured Nostr relay acknowledgement quorum.
- Record an X post as successful only after receiving or reconciling its public post ID.
- A timeout after an X request may have been accepted is `UNKNOWN`, not an automatic retry.
- Cross-platform posting cannot be atomic. Expose partial completion and never claim rollback.

## Logging rules

Logging is allowlist-based. Adding a field requires a privacy review.

Allowed by default:

- Random job ID.
- Normalized job state and stable error code.
- Selected Nostr exit country after dispatch and the non-secret X endpoint identifier.
- Public X post ID and Nostr event ID after success.
- Relay acknowledgement counts without raw messages.
- Component version and bounded duration metrics.

Prohibited:

- Draft or published content, links, media, or approval payloads.
- X access tokens, refresh tokens, PKCE verifier, authorization code, passwords, cookies, or Authorization headers.
- Nostr private keys, NIP-46 connection secrets, encrypted signer payloads, or raw signed events.
- VPN private keys, provider credentials, account identifiers, configuration bodies, or future country choices.
- Exact exit IP, home IP, VPN endpoint IP, raw DNS answers, or packet payloads.
- Raw HTTP request or response bodies and raw relay notices. Normalize remote errors because they may echo content or secrets.
- Process environment or command lines.

Debug mode must not relax these rules. Production builds must disable verbose HTTP tracing and secret-bearing core dumps.

## Retention

- Encrypt drafts and approved queued content at rest.
- Keep content only until both platforms reach a resolved state. Unknown or partial jobs retain the minimum encrypted payload needed for safe reconciliation.
- After resolution, remove local content and keep minimal encrypted operational metadata for seven days.
- After seven days, delete operational metadata and destroy expired encryption keys where key separation permits cryptographic erasure.
- Keep only aggregated endpoint-health metrics for 90 days. They must not contain job IDs, content, account identifiers, exact IPs, or per-post timestamps.
- Exclude tokens, VPN keys, drafts, and raw job databases from ordinary backups. Any encrypted recovery backup needs a documented owner, purpose, expiry, and restore test.
- Deletion on SSD, journaling filesystems, snapshots, and provider-managed storage cannot be guaranteed byte-for-byte. Documentation must say so.

See [ADR 0003](adr/0003-data-retention.md) for the decision and exceptions.

## Dependency and build security

- Prefer standard-library and operating-system facilities before adding a dependency.
- Pin direct dependencies and commit the appropriate lock file.
- Review new dependencies for maintenance, license, published vulnerabilities, transitive footprint, network behavior, and safer alternatives.
- Generate an SBOM and run dependency, secret, static-analysis, and license checks for release artifacts.
- Build release artifacts from a clean checkout with reproducible commands and signed provenance where the toolchain supports it.
- Do not bypass checks with `--no-verify`, swallowed exceptions, expected-failure markers, or hardcoded test-only routes.
- Treat VPN configuration and Nostr relay lists as untrusted input and validate size, scheme, host, port, and identifier format.

## Operational controls

- Bind the UI only to the management VPN interface, serve TLS, and reject access through egress or public interfaces.
- Require two registered WebAuthn passkeys plus an offline recovery code. Require an authenticated, CSRF-protected session for approvals, recovery, emergency stop, and account re-pairing.
- Rate-limit locally below current platform limits and provide an immediate stop control.
- Do not automatically change behavior to work around 401, 403, 429, policy errors, suspension, or geographic denial.
- Time synchronization must be healthy before Nostr signing, but clock failure must not trigger insecure fallback.
- Health checks must use the same network isolation as the operation they authorize and expire after 90 seconds. Three failures quarantine an endpoint; route, DNS, static-IP, country, or TLS mismatch quarantines it immediately.
- Provider and country health data expires quickly and is revalidated at dispatch.

## Incident response

On suspected token, signer, or VPN-key compromise:

1. Stop the scheduler and destroy active worker namespaces.
2. Revoke X authorization and NIP-46 client access.
3. Rotate affected VPN keys and local encryption keys.
4. Preserve sanitized state needed to identify affected public post and event IDs.
5. Inspect for unauthorized public posts through authoritative platform interfaces.
6. Correct the root cause, not only the exposed credential.
7. Rerun all three adversarial rounds before restoring unattended operation.

Do not place real secrets or exploitable details in a public issue. Use [GitHub Private Vulnerability Reporting](https://github.com/s00ly/nomadposting/security/advisories/new) and share only the minimum redacted reproduction material needed to investigate. No production release exists; reports against `main` are accepted. Public issues are appropriate for non-exploitable design questions and hardening proposals.

## Security-maintainer authority

The active security maintainer is listed in
[MAINTAINERS.md](../MAINTAINERS.md). The project currently has one security
maintainer, which is an explicit bus-factor limitation.

The security maintainer may access private advisories, invite a minimum set of
qualified reviewers, merge embargoed fixes, stop publication, revoke
compromised artifacts, coordinate disclosure, and require credential rotation.
Any medium-or-higher finding resets the affected verification work and all
three production adversarial rounds. No administrator may waive that reset by
merging, changing a label, or editing the verification record.

Code of Conduct reports use the separate private channel defined in
[CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md). Vulnerability reporting must not be used for
interpersonal or community-moderation complaints.

## Release gates

A release is blocked unless:

- The threat model and ADRs match implemented behavior.
- Unit, integration, network-namespace, IPv4, IPv6, DNS, and crash-recovery tests pass from a clean environment.
- Physical-interface capture proves that the separate X and Nostr workers, signer, resolver, and verifier traffic cannot bypass WireGuard.
- Canary-secret scans find no disclosure in logs, state, process metadata, crash artifacts, or backups.
- Ambiguous X outcomes and mixed Nostr acknowledgements preserve truthful states without blind duplicates.
- The second-account, geotag, non-API X, X-rotation, and direct-route abuse tests are rejected.
- Three clean adversarial rounds pass with no unresolved medium-or-higher finding.

Evidence must name the command, environment, artifact, and result. A successful build alone is not evidence that privacy controls work.

## Primary references

- [WireGuard routing and network namespaces](https://www.wireguard.com/netns/)
- [Nostr NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [Nostr NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)
- [X OAuth 2.0 with PKCE](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token)
- [X Developer Policy](https://docs.x.com/developer-terms/policy)
- [X automation rules](https://help.x.com/en/rules-and-policies/x-automation)
