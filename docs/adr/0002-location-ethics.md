# ADR 0002: VPN Country Selection and Location Ethics

- Status: Accepted
- Date: 2026-07-14

## Context

The application selects a VPN exit country for each Nostr publication and uses one dedicated France exit for X. An exit country is transport metadata. It is not reliable evidence of the operator's physical location. VPN provider labels and GeoIP databases can be stale, inconsistent, virtualized, or wrong, and no application-level check can cryptographically prove where a server is physically located.

Using the exit country as a geotag or personal-location claim would mislead readers. Country rotation must also not become a mechanism to bypass sanctions, platform availability, content controls, suspensions, or rate limits.

## Decision

- Treat the selected value as `exit_country`, never `user_location`.
- Maintain an explicit allowlist of legally and contractually acceptable countries and provider configurations.
- Apply random country rotation only to Nostr. Require at least three healthy approved countries for normal rotation.
- Choose at dispatch with an operating-system CSPRNG and unbiased sampling.
- Select uniformly by country, excluding the immediately previous country, then select a healthy exit within that country.
- If no different healthy country is available, pause the post with a visible error. Do not reuse the prior country, select a disallowed country, or bypass the VPN silently.
- Do not precompute, expose, or log future country choices.
- Omit X geotags and Nostr location tags by default. Never derive them from the VPN exit.
- Show “No geotag” during approval and call the post-publication value “VPN exit country.”
- Use provider metadata and, where justified, independent GeoIP observations to detect disagreement. Do not call the result proof of physical location.
- Do not alter country selection in response to platform denial in order to work around geographic or enforcement controls.
- Pin X to one registered France endpoint. Production `rotating_country` remains disabled and cannot be enabled by an error, challenge, rate limit, or restriction response.

## Consequences

Positive:

- The UI does not misrepresent network routing as physical presence.
- Dispatch-time selection makes future country choices unavailable to an observer who sees only stored jobs.
- Country-first selection avoids bias toward countries with more configured servers.
- Fail-closed behavior preserves the stated no-repeat policy.

Costs and residual risks:

- Posts may be delayed when only one country is healthy.
- Health filtering changes the eligible set and therefore the observed distribution.
- Providers, platforms, and timing observers may still correlate activity.
- GeoIP disagreement may block a legitimate exit, while agreement still does not prove physical location.
- The stable X endpoint reduces country-change risk but does not prevent X from challenging VPN traffic.

## Rejected alternatives

- Attach the VPN country as a public geotag: rejected as misleading.
- Use every provider country automatically: rejected because legal, contractual, security, and reliability review must precede inclusion.
- Weight selection by number of servers: rejected because it biases the country distribution.
- Use a time-seeded pseudorandom generator: rejected because future choices may be predictable.
- Retry from another country after platform geographic denial: rejected because it can become restriction circumvention.
- Rotate X per post: rejected for production pending a test-account pilot and written X clarification or a new explicit risk decision.
- Claim cryptographic proof of exit location: rejected because the available evidence does not support it.

## Verification

- Property tests show the prior country, unhealthy entries, and disallowed entries are never selected.
- A one-country healthy pool returns `NO_ELIGIBLE_ALTERNATE` and emits no platform traffic.
- Deterministic fake-random tests cover unbiased index mapping and country-first selection.
- A large simulation detects gross distribution defects but is not used as proof of unpredictability.
- Request-builder tests prove no VPN-derived X geotag or Nostr location tag is emitted.
- UI and logs distinguish exit country from physical location.
- Policy tests prove a platform denial cannot activate a hidden country or direct-route fallback.
- X policy tests prove every authorization, refresh, publish, and reconcile operation uses the registered France endpoint.

## Revisit when

Revisit this ADR before adding user-supplied location, public geotags, custom country weights, multi-hop routing, jurisdiction-aware content rules, or automatic provider onboarding.
