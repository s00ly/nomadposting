# Threat Model

This document is a design and release-test baseline. It does not certify that a particular build or deployment has met the controls below.

## Purpose and privacy claim

iVPN publishes one user's approved content to one X account and one Nostr identity. Nostr publication selects a healthy VPN exit in a different allowed country from the previous Nostr post. X publication and every X token operation use one dedicated France exit. Each platform attempt runs in its own fail-closed network namespace.

The defensible privacy claim is narrow: the design reduces disclosure of the host's source IP to X and Nostr relays. It does not make the author anonymous. X can link requests through the OAuth token, account, developer application, content, and timing. Nostr events are intentionally linkable through the stable public key and signature. A VPN provider or sufficiently capable timing observer may correlate tunnel ingress and egress.

The app must not describe a VPN exit country as the user's physical location or promise anonymity, untraceability, or immunity from platform enforcement.

## Scope

In scope:

- Text and links approved by the user before queueing.
- One X account authenticated through the official X API and OAuth.
- One Nostr public key, preferably controlled by a NIP-46 signer.
- A Linux posting worker isolated in a fresh network namespace for each platform attempt.
- A provider-neutral pool of VPN provider, country, and exit tuples.
- DNS, IPv4, IPv6, token refresh, Nostr signing, relay publication, and X publication over the selected tunnel.
- Minimal encrypted job state needed to resolve failures and prevent duplicate posts.

Out of scope:

- Multiple account operation, account farms, or third-party accounts.
- Hiding that two posts came from the same X account or Nostr key.
- Defeating a global passive observer or a compromised host administrator.
- Circumventing rate limits, suspensions, sanctions, geographic restrictions, or other platform controls.
- X website automation, session-cookie reuse, CAPTCHA bypass, automated replies, mentions, or direct messages.
- Claiming or attaching a physical location inferred from the VPN exit.

## Assets

| Asset | Required property | Impact if compromised |
| --- | --- | --- |
| X access and refresh tokens | Confidentiality, integrity, revocability | Unauthorized posting or account access |
| Nostr signing authority | Confidentiality and tightly scoped authorization | Irreversible impersonation through signed events |
| VPN private keys and provider credentials | Confidentiality and isolation from workers | Unauthorized VPN use, correlation, or egress bypass |
| Draft and queued content | Confidentiality and integrity until publication | Premature disclosure or altered publication |
| Post approval | Authenticity and auditability | Content published without informed consent |
| Country-selection state | Integrity and unpredictability before dispatch | Predictable or disallowed routing |
| Job and platform identifiers | Integrity | Duplicate posts, false success, or lost recovery state |
| Network policy | Integrity and availability | Direct source-IP disclosure or silent posting failure |
| Logs and crash artifacts | Data minimization | Secondary leakage of secrets, content, IPs, or behavior |

## Architecture and trust boundaries

1. The private UI binds only to the management VPN, uses TLS, and requires two registered WebAuthn passkeys plus an offline recovery code. It shows exact content, destination platforms, and the absence of geotags before approval.
2. The unprivileged controller stores the approved job. At dispatch it chooses a Nostr country using the operating system CSPRNG and chooses the registered dedicated France endpoint for X.
3. A narrow privileged network broker creates a fresh network namespace and WireGuard interface for each platform attempt. It accepts only a validated job ID, platform, and registered endpoint ID, never content, credentials, routes, addresses, paths, or commands.
4. The non-root posting worker receives short-lived credential handles and runs with only loopback and the selected WireGuard interface.
5. A worker-specific resolver configuration uses only the VPN gateway resolver. IPv6 is disabled for version 1. nftables denies all other egress and blocks private, loopback, link-local, metadata, management, and peer networks.
6. The X worker refreshes and uses X credentials only through the dedicated France exit. The Nostr worker requests a NIP-46 signature and publishes the same signed event ID to every approved relay through the selected Nostr exit.
7. The controller records independent normalized outcomes and public platform identifiers, then destroys each namespace, tmpfs, interface, and ephemeral credential handle.

Trust boundaries:

- User to management-VPN UI: passkey authentication, CSRF defense, approval, and content integrity.
- Controller to privileged network broker: untrusted identifier input crossing a privilege boundary.
- Secret store to worker: high-value credentials crossing into an ephemeral process.
- Worker to VPN provider: source host is visible to the provider; destinations and timing may be visible, while TLS protects application payloads.
- Dedicated X exit to X: stable exit IP, timing, account, and public content are observable.
- Selected Nostr exit to Nostr relays: rotating exit IP, timing, public key, event ID, and public content are observable.
- Client to NIP-46 signer: signer metadata and timing may be visible to signer relays; the signer sees the event it authorizes.

The VPN provider, public relays, GeoIP services, and platform responses are not trusted to be correct or privacy-preserving. TLS certificate validation is mandatory, but it does not hide destination metadata from the VPN provider.

## Security and privacy invariants

- There is no route from a posting worker to a physical interface.
- Egress is drop-by-default and permitted only through the selected WireGuard interface.
- DNS never uses the host stub resolver or a resolver outside the tunnel.
- IPv6 is tunneled or unavailable. It never silently falls back to the host route.
- Tunnel failure, resolver failure, country disagreement, or an empty eligible pool fails closed.
- The browser is absent from the posting path, so WebRTC cannot create a publishing-path leak.
- X server-side OAuth token exchange, token refresh, publication, and reconciliation use the same registered dedicated France endpoint. The browser authorization page uses the browser's own route. Production X country rotation is disabled.
- Nostr country selection occurs at dispatch, uses an OS-backed CSPRNG and unbiased sampling, and excludes the previous Nostr country.
- One Nostr lease is pinned across every relay attempt and retry for that event. If fewer than three approved countries are healthy or no eligible alternative exists, Nostr publication remains queued. The app never reuses the prior country or bypasses the VPN silently.
- X and Nostr execute in separate namespaces and resolve independently. Failure of one platform does not authorize reuse or rerouting of the other platform's request.
- The core app never receives a Nostr private key when NIP-46 is configured.
- X writes use only the official API. OAuth authorization alone is not consent to publish.
- Ambiguous X results are marked unknown and reconciled. They are not blindly retried.
- Nostr success requires the configured relay acknowledgement quorum.
- Cross-platform publication is not atomic. Partial success is reported as partial.

## Threat actors

- Local unprivileged malware trying to read drafts, tokens, or VPN keys.
- A malicious or compromised posting worker trying to escape the network namespace.
- A compromised VPN provider observing subscriber identity, destinations, and timing.
- A malicious VPN exit attempting DNS manipulation or TLS interception.
- A malicious Nostr relay recording source metadata, rejecting events, or returning false status.
- An attacker with a stolen X token or NIP-46 client key.
- A network observer correlating the user's encrypted VPN connection with exit traffic.
- An operator attempting to repurpose the application for platform evasion or misleading location claims.
- Accidental operator error, stale configuration, software defects, and crash recovery.

Host root compromise and a global passive observer are acknowledged residual risks, not solved threats.

## STRIDE analysis

| Category | Threat | Required control | Residual risk and proof |
| --- | --- | --- | --- |
| Spoofing | Attacker reuses an X token | OS or TPM-backed encryption, least scopes, refresh-token rotation, revoke flow | A compromised user session can still authorize misuse. Prove revocation and token isolation in tests. |
| Spoofing | Client connects to an attacker-controlled NIP-46 signer | Pin the expected signer public key, validate the connection secret, request minimal signer permissions | A compromised signer remains authoritative. Prove key mismatch and unexpected-kind rejection. |
| Spoofing | VPN or DNS attacker redirects X or a relay | Strict TLS hostname and certificate validation; no insecure override | A valid but malicious public CA remains a wider ecosystem risk. Prove bad-certificate rejection. |
| Tampering | Controller injects commands into the privileged broker | Typed allowlisted identifiers, fixed system calls, no shell interpolation, least Linux capabilities | A broker defect crosses the strongest local boundary. Fuzz and privilege-test its request parser. |
| Tampering | Draft changes after approval | Bind approval to a content hash, target set, and geotag state; require reapproval after any mutation | A compromised host can alter both UI and state. Verify hash mismatch blocks sending. |
| Tampering | Forged relay acknowledgement or X response | Validate protocol shape, event ID, Nostr signature, TLS, and returned account context | Remote services can still reject or later remove content. Reconcile from authoritative endpoints. |
| Repudiation | Operator disputes a publication | Record approval hash, job ID, public platform IDs, and normalized state transitions without recording secret content | Local audit state is not a third-party legal proof. Integrity checks show local tampering only. |
| Information disclosure | Direct route exposes the host IP | Per-platform namespace with only loopback and WireGuard, plus drop-by-default nftables | Kernel or root compromise defeats isolation. Prove with physical-interface packet capture. |
| Information disclosure | DNS, IPv6, or WebRTC leaks source metadata | Per-worker resolver, tunneled or disabled IPv6, no browser in posting worker | OAuth performed in an ordinary browser can still disclose its IP. Treat OAuth isolation separately. |
| Information disclosure | Tokens or content enter logs, argv, environment, crash dumps, or backups | Secret handles, allowlist-only logging, no raw HTTP logging, disabled core dumps, backup exclusions | Memory inspection by a privileged attacker remains possible. Run seeded-canary scans. |
| Denial of service | VPN, resolver, signer, X, or relays are unavailable | Bounded retries, circuit breakers, explicit queued or partial states, no direct fallback | Availability is deliberately traded for privacy. Exercise every dependency failure. |
| Denial of service | Nostr health filtering leaves fewer than three countries or no alternative | Queue with `NO_ELIGIBLE_ALTERNATE` and send no relay traffic | A strict minimum and no-repeat rule can delay posts. This is intentional. |
| Elevation of privilege | Worker reads VPN keys or changes routes | Worker is non-root; raw VPN keys remain in root-only broker storage; capabilities are dropped | Kernel vulnerabilities remain out of scope. Verify `/proc`, filesystem, and capability boundaries. |
| Elevation of privilege | Private UI is reached outside the management VPN or an approval session is stolen | Bind only to the management interface, use TLS, require two enrolled WebAuthn credentials, protect state changes with CSRF tokens, and reject proxy trust by default | A compromised authenticated browser session remains dangerous. Test non-management-interface refusal, origin checks, and passkey recovery. |

## LINDDUN analysis

| Category | Privacy threat | Treatment and limit |
| --- | --- | --- |
| Linkability | X links all posts by account and token; Nostr links them by public key; identical content and timing link the platforms | Accepted and disclosed. Country rotation does not change account-level linkability. Optional timing changes must not become deceptive or evade platform controls. |
| Identifiability | Account profile, Nostr key history, content, and OAuth records identify the operator | Data minimization reduces local leakage only. The app cannot promise identity anonymity. |
| Non-repudiation | Nostr signatures provide strong public attribution | Inherent to Nostr and not mitigated. Protect signing authority and display this consequence before pairing. |
| Detectability | ISP sees VPN usage; provider sees session timing; X sees the dedicated exit; Nostr relays see rotating exit ASNs | Accepted residual metadata. Multiple independent providers can reduce concentration but not eliminate timing analysis. |
| Disclosure | Drafts, tokens, exit IPs, provider IDs, or relay errors leak through storage and logs | Encrypt queued content, minimize retention, normalize errors, prohibit raw payload and network metadata logging. |
| Unawareness | User assumes VPN country is physical location or anonymity | UI and documentation state that it is transport egress only, show no geotag, and avoid anonymity claims. |
| Non-compliance | Automation violates X consent, spam, rate-limit, privacy, or location rules | One authorized account, exact-content preview, official API, conservative rate caps, clear stop control, and policy review before release. |

## Abuse and evasion cases

The application must reject or exclude:

- Adding a second X account or Nostr identity without an explicit local administrative re-pairing flow.
- Browser automation, scraping, session-cookie authentication, CAPTCHA handling, or non-API X writes.
- Features intended to evade rate limits, enforcement, suspension, blocks, sanctions, or geographic availability rules.
- VPN-derived geotags, claims that the user is physically in an exit country, or automated location narratives.
- Identical amplification across account fleets, automated mentions, replies, direct messages, or unsolicited engagement.
- Silent fallback to the host connection, an unapproved country, the prior Nostr country, or an alternate X country.

The control is not merely a terms notice. The single-account data model, API-only X adapter, no-geotag request builder, and fail-closed network path are implementation requirements.

## Acceptance evidence

Network evidence:

- Physical-interface packet capture during successful and failed jobs contains only VPN endpoint traffic. It contains no X, Nostr relay, signer relay, GeoIP, or DNS destination outside the tunnel.
- Forced tunnel loss before and during DNS, X token refresh, X reconciliation, NIP-46 signing, relay publication, and X publication causes no direct traffic and no false success.
- IPv4 and IPv6 tests show both families use the selected tunnel, or IPv6 is unreachable inside the namespace.
- A posting worker cannot see a physical interface, alter routes, read root-only VPN configuration, or gain network administration capability.

Identity and secret evidence:

- Seeded canary secrets do not appear in logs, journals, process arguments, environment variables, temporary storage, crash artifacts, backups, or retained job metadata.
- Revoked X authorization cannot publish and leaves no usable refresh token.
- The NIP-46 signer rejects the wrong client, wrong connection secret, and every ungranted event kind.
- Nostr event IDs and signatures verify against NIP-01 serialization before publication.

Workflow evidence:

- Content mutation after approval blocks dispatch until reapproved.
- Property tests prove that a disallowed or unhealthy Nostr country is never selected, at least three healthy countries are required, and the immediately previous country is excluded.
- Policy tests prove that X always receives the registered France endpoint and never switches endpoint after a 403, 429, challenge, restriction, or ambiguous response.
- Simulation detects gross distribution bias, while the security argument remains the OS CSPRNG, not the simulation.
- Mixed Nostr relay responses produce the configured quorum result.
- An X timeout after request transmission becomes `UNKNOWN_X`; reconciliation cannot create a blind duplicate.
- Restart at every job-state boundary preserves confirmed public IDs and never bypasses the tunnel.
- Partial X or Nostr success is shown as partial, not complete.

## Three clean adversarial rounds

Each round starts from a clean environment and produces packet captures, normalized logs, test output, and a finding register. Any medium-or-higher finding requires root-cause correction and a complete rerun of all three rounds.

### Round 1: Egress escape and kill switch

- Exercise both platform namespaces, tunnel loss, endpoint change, DNS outage, stale WireGuard handshake, host resolver availability, IPv6 availability, worker crash, and broker crash.
- Capture the physical and WireGuard interfaces.
- Pass only if platform, relay, signer, verifier, and DNS traffic is absent from the physical interface and every unsafe condition fails closed.

### Round 2: Secret and privacy extraction

- Use non-production canary values for each secret class.
- Attempt extraction through logs, error strings, HTTP tracing, argv, environment, `/proc`, temporary files, database pages, journal, core dumps, backups, and a compromised unprivileged worker.
- Pass only if no canary appears outside its designated encrypted store or short-lived worker memory, and the worker cannot read VPN key material.

### Round 3: Protocol abuse, recovery, and scope control

- Inject X 401, 403, 429, 5xx, bad TLS, timeout-before-send, timeout-after-send, revoked refresh token, and mismatched account responses.
- Inject Nostr invalid signatures, false or mixed acknowledgements, duplicate events, unavailable signer, wrong signer key, and relay quorum loss.
- Restart at every state transition, attempt a second account, attempt a geotag, attempt a non-API X path, and attempt to rotate X after a policy or ambiguous response.
- Pass only if no duplicate is blindly created, partial and unknown states remain truthful, the second identity and geotag are rejected, X remains on its dedicated endpoint, and no alternate network or X automation path exists.

## Residual risk review

Before release, the owner must explicitly accept or change these residual risks:

- Account, public-key, content, and timing linkability.
- VPN-provider and hosting-provider metadata visibility.
- Possible X challenge or enforcement caused by VPN use even though production X country rotation is disabled.
- GeoIP inaccuracy and inability to prove the physical country of an exit.
- Loss of availability when privacy controls fail closed.
- Host administrator, kernel compromise, and global timing correlation.

## Primary references

- [WireGuard routing and network namespaces](https://www.wireguard.com/netns/)
- [Nostr NIP-01 event and relay protocol](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [Nostr NIP-46 remote signing](https://github.com/nostr-protocol/nips/blob/master/46.md)
- [X OAuth 2.0 Authorization Code with PKCE](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token)
- [X create-post integration guide](https://docs.x.com/x-api/posts/manage-tweets/integrate)
- [X Developer Policy](https://docs.x.com/developer-terms/policy)
- [X automation rules](https://help.x.com/en/rules-and-policies/x-automation)
- [NIST SP 800-90C random bit generator guidance](https://csrc.nist.gov/pubs/sp/800/90/c/final)
