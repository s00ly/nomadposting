# Verification Record

Date: 2026-07-15

This record separates code-level evidence from production network evidence. The
repository is a dry-run control plane and safety scaffold. It is not a working
VPN cross-poster, and live mode is deliberately rejected at configuration load.

## Evidence collected

| Check | Result | Evidence |
|---|---|---|
| Go version | PASS | Pinned Go 1.26.5 toolchain used for every command below. |
| Formatting | PASS | `gofmt -d cmd internal` returned no diff. |
| Module integrity | PASS | `go mod verify` returned `all modules verified`. |
| Complete test suite | PASS | `go test -count=1 ./...` and a final `go test -count=3 ./...` passed all 10 packages. The repository contains 59 named tests. |
| Static analysis | PASS | `go vet ./...` returned no findings. |
| Reachable vulnerability scan | PASS WITH NOTE | `govulncheck v1.6.0` found zero symbol- or package-level vulnerabilities. See dependency note below. |
| Linux build | PASS | Both `cmd/ivpn` and `cmd/netbroker` cross-built for `linux/amd64` with `CGO_ENABLED=0` and `-trimpath`. |
| Race detector | PASS IN CI; NOT RUN LOCALLY | This Windows environment has no CGO compiler. `go test -race` correctly failed locally with `-race requires cgo`. The pinned Ubuntu workflow passed the race suite in [run 29382281777](https://github.com/s00ly/nomadposting/actions/runs/29382281777). |
| OpenTofu validation | NOT RUN | OpenTofu is not installed in this environment. The infrastructure directory is a topology manifest, not resource definitions. |

## Code-level adversarial rounds

These are clean unit and integration-test rounds. They do not satisfy the Linux
packet-capture rounds required for live release.

1. Routing and protocol boundaries: PASS
   - `go test -count=1 ./internal/egress ./cmd/netbroker ./internal/platform`
   - Covered country-uniform random selection, no adjacent repeat, stale and
     quarantined endpoints, fixed X policy, typed broker input, ambiguous X
     results, bounded responses, relay quorum, and signer-envelope mutation.
2. Credential and disclosure boundaries: PASS
   - `go test -count=1 ./internal/secure ./internal/auth ./internal/store ./internal/web`
   - Covered AEAD context binding and tampering, WebAuthn policy, CSRF, replay,
     recovery-code rotation and rate limiting, encrypted records, security
     headers, untrusted flash rejection, and pre-dispatch country hiding.
3. State, duplicate, and recovery boundaries: PASS
   - `go test -count=1 ./internal/domain ./internal/app ./internal/platform ./internal/store`
   - Covered approval-hash binding, unsafe transitions, schedule and emergency
     checks, exact Nostr event reuse, X no-blind-retry behavior, compare-and-swap
     state races, cryptographic content erasure, and retention of unresolved jobs.

## Browser verification

The local dry-run app was inspected at desktop and 390 px mobile widths using
the in-app browser.

- PASS: dashboard, composer, exact preview, approval, and secure-bootstrap views
  rendered without console errors or third-party resources.
- PASS: computed palette used graphite backgrounds, orange actions, purple
  focus and cryptographic state, and readable light-gray text.
- PASS: keyboard focus was visible as a 3 px purple outline.
- PASS: neither future nor selected country appeared before dispatch.
- PASS: exact content and SHA-256 approval hash appeared on preview; approved
  content did not appear on the job dashboard.
- FIXED AND REGRESSED: a raw `?msg=` query value could impersonate a trusted
  status banner. Redirects now use a closed set of message codes, with a test
  rejecting untrusted text.
- FIXED AND RECHECKED: grid minimum sizing caused 6 px mobile overflow. Explicit
  `min-width: 0` constraints removed horizontal overflow.
- NOT PROVEN: full WCAG 2.2 AA audit, real screen-reader behavior, every focus
  path, 200% zoom, and automated visual-regression baselines.

## Dependency note

The verbose vulnerability scan reported module advisory `GO-2026-5932` for the
unmaintained `golang.org/x/crypto/openpgp` package, with no fixed version. The
application neither imports nor calls that package. The required module enters
through WebAuthn metadata and OCSP:

```text
ivpn/internal/auth
github.com/go-webauthn/webauthn/webauthn
github.com/go-webauthn/webauthn/metadata
github.com/go-webauthn/x/revoke
golang.org/x/crypto/ocsp
```

This is not a reachable finding, but it remains visible in the release record.
Reassess it on every dependency update.

## Unsatisfied release gates

| Severity | Gate | Current proof |
|---|---|---|
| HIGH | Live per-job namespace executor, WireGuard, validating DNS, nftables, UID/capability drop, teardown | Missing by design. The broker refuses execution. |
| HIGH | Packet captures proving zero fallback during every failure phase | Missing. Requires a disposable Linux test host and real tunnels. |
| HIGH | Broker-backed dispatcher and pinned per-platform HTTP/WebSocket transports | Missing. Approved jobs remain queued; OAuth and publishing are not wired into a live worker. |
| HIGH | Concrete NIP-46 transport, signer identity/permission enforcement, and Schnorr verification | Missing. Protocol construction and boundary tests exist only. |
| HIGH | TPM or operating-system secret-store sealing | Missing. Strict `_FILE` loading exists, but the master key is not sealed by this application. |
| MEDIUM | X ambiguous-result reconciliation through the same dedicated exit | Missing. Manual reconciliation records intent but performs no remote lookup. |
| MEDIUM | X weighted-length conformance against maintained platform vectors | Partial. The local implementation rejects rather than truncates, but the platform remains authoritative. |
| MEDIUM | Encryption of every exact operational metadata field | Partial. Content, credentials, receipts, audit details, auth records, and tokens are envelope-encrypted; job state, timestamps, destination flags, and payload hashes remain queryable plaintext in SQLite. |
| MEDIUM | Provisioned gateways, resolvers, health probes, static-address/country verification, budgets, and encrypted remote state | Missing. OpenTofu records topology only. |
| MEDIUM | Live Nostr relay review, NIP-11/NIP-65 onboarding, and TCP 443 WebSocket tests | Missing. Relay identifiers and quorum behavior are test fixtures. |
| MEDIUM | Seven-day canary and production observation | Missing because all preceding live gates are open. |
| MEDIUM | Complete accessibility and visual-regression suite | Partial browser inspection only. |

Any implementation that closes a MEDIUM-or-higher gate must rerun all affected
tests and restart the three production adversarial rounds. None may be waived,
xfail-marked, or bypassed.

## Release decision

**NO-GO for live credentials, cloud provisioning, or publication.**

**GO for local dry-run review and continued implementation.** The application
fails closed, stores no Nostr private key, does not claim physical location, and
does not provide browser automation, residential proxies, enforcement evasion,
or error-triggered IP switching.
