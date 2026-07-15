# ADR 0001: Product and Privacy Boundaries

- Status: Accepted
- Date: 2026-07-14

## Context

The product sends one user's posts to X through a dedicated France VPN exit and to Nostr through VPN exits selected from different approved countries. VPN routing can reduce disclosure of the host source IP to the destination service. It cannot remove the stable identifiers created by an X account, OAuth token, X developer application, Nostr public key, signature, content, or timing.

Without an explicit boundary, the feature could be misrepresented as anonymity or repurposed for account farms, platform enforcement evasion, misleading location claims, or non-API automation. Those uses also weaken the technical design because they encourage unsafe fallbacks and duplicate identities.

## Decision

iVPN is a single-operator, single-X-account, single-Nostr-identity source-IP privacy tool.

- X and Nostr publication run in separate fail-closed namespaces. X uses one registered France endpoint. Nostr selects a country at dispatch and pins that lease across its signer and relay attempts.
- X integration uses the official API and OAuth. The application contains no X website automation, session-cookie reuse, CAPTCHA workflow, or rate-limit bypass.
- Nostr uses a stable public key and preferably a NIP-46 signer with least event-kind permission.
- The application does not claim to make the author anonymous, unlinkable, untraceable, or immune to enforcement.
- The application does not support account fleets, third-party accounts, automated mentions, replies, direct messages, or unsolicited engagement.
- Re-pairing to a different identity requires explicit local administrative action and invalidates queued approvals.
- Network isolation fails closed. It never falls back to the host connection or an unapproved country.
- OAuth authentication is not consent to publish. Exact content, destinations, and geotag state are approved before queueing.

## Consequences

Positive:

- The product claim matches what the network design can test.
- Single-identity controls reduce the most direct abuse paths.
- Official APIs and explicit consent create a reviewable compliance boundary.
- Fail-closed behavior makes source-IP leakage a release-blocking defect.

Costs and residual risks:

- Availability is lower when a tunnel, country, signer, relay, or platform is unavailable.
- X and Nostr posts remain linkable to their accounts and often to each other.
- VPN use may trigger a platform security challenge or enforcement. X country rotation remains disabled in production because X has not documented the risk of rapid authenticated country changes.
- A compromised host administrator, VPN provider, or strong timing observer remains capable of correlation.

## Rejected alternatives

- Multi-account support: rejected because it expands abuse potential, token isolation complexity, and correlation risk beyond the stated use case.
- Browser automation for X: rejected because X requires API-based automation and because a browser adds cookies, fingerprinting, DNS, and WebRTC leak paths.
- Best-effort direct fallback: rejected because it defeats the core privacy property.
- One randomized country shared by both platforms: rejected because production X rotation has unresolved account-security and policy risk.
- Anonymity marketing: rejected because the same X account and Nostr public key provide direct linkage.

## Verification

- Data model and pairing tests reject a second active X user ID or Nostr public key.
- Integration tests show every X write uses the official API adapter.
- Policy tests show X always uses the registered France endpoint and cannot switch on error, while Nostr applies the approved no-adjacent-repeat policy.
- Packet capture shows no direct destination traffic when the tunnel fails.
- UI tests prove content or target mutation invalidates approval.
- Documentation and product copy use “exit country” and “source-IP privacy,” not physical-location or anonymity claims.

## Revisit when

Revisit this ADR before adding multiple users, multiple identities, replies, direct messages, media automation, a browser component, non-Linux support, or a claim stronger than source-IP privacy.
