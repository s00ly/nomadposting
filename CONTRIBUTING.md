# Contributing to NomadPosting

NomadPosting welcomes design reviews, tests, documentation, and code that make
its privacy and safety boundaries easier to verify. The repository is a
dry-run research preview. Do not use real platform, VPN, signer, cloud, or user
credentials while developing or testing it.

Read the [threat model](docs/THREAT_MODEL.md),
[security policy](docs/SECURITY.md),
[verification record](docs/VERIFICATION.md), and
[governance policy](GOVERNANCE.md) before changing behavior.

## Before opening an issue

- Use a public issue for reproducible dry-run bugs, non-exploitable design
  questions, feature proposals, and threat-model challenges.
- Do not disclose a vulnerability, credential, private account identifier,
  production configuration, sensitive packet capture, or exploit path in an
  issue. Follow the private process in
  [docs/SECURITY.md](docs/SECURITY.md).
- Search existing issues and verification gates before filing a duplicate.
- State what you observed and what evidence would prove the desired result.

## Contribution terms

Contributions are accepted under the same
[AGPL-3.0-or-later](LICENSE) terms as the project. The project uses the
[Developer Certificate of Origin 1.1](DCO) and does not require a Contributor
License Agreement or copyright assignment.

Every commit made after DCO adoption must include a `Signed-off-by:` trailer
matching the commit author. Add it automatically with:

```sh
git commit -s
```

The sign-off certifies the statements in the DCO. It is not a decorative
footer. The name and email become part of permanent public Git history, so use
an identity you are authorized to publish. Every co-author must provide a
matching sign-off.

If a commit is missing its sign-off, amend or rebase that commit. Do not add a
later commit that purports to sign an earlier one. The `dco / signoff` check
rejects unsigned commits after the adoption point.

## Development workflow

1. Start from the current default branch and create a focused topic branch.
2. Add a failing test or reproducible check before fixing a defect when
   practical.
3. Keep the change limited to one reviewable purpose.
4. Update every security, threat-model, deployment, and verification claim
   affected by the change.
5. Commit with `git commit -s` and open a pull request using the repository
   template.

The Linux security baseline and CI run:

```sh
gofmt -w ./cmd ./internal
go mod verify
bash ./scripts/check-dco-tests.sh
bash ./scripts/check-licenses.sh
go test -race -count=1 ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

On Windows, the race detector may require a supported CGO compiler. Run the
non-race test suite locally and treat the pinned Ubuntu CI result as the race
gate. A local build is not evidence that Linux network isolation works.

## Change standard

A pull request must:

- explain the behavior, trust boundary, failure state, and user-visible claim;
- include tests or reproducible evidence proportional to risk;
- preserve fail-closed behavior and the single-account, official-API scope;
- update relevant threat-model, security, deployment, ADR, or verification
  documents;
- pass formatting, tests, static analysis, vulnerability,
  dependency-license, and DCO checks without bypasses;
- contain no secret, real credential, production VPN configuration, private
  account identifier, or unredacted sensitive capture.

Do not use `--no-verify`, expected-failure markers, swallowed errors, hardcoded
test bypasses, browser or cookie automation, residential proxies, or
enforcement-evasion behavior. Medium-or-higher security or privacy findings
reopen the affected verification work and reset all three production
adversarial rounds.

## Security-sensitive changes

Changes affecting authentication, cryptography, secrets, network egress,
signing, platform transports, state reconciliation, logging, retention,
deployment, CI, or release claims require:

- a named threat and trust boundary;
- negative tests for failure and abuse paths;
- an ADR when the security boundary or accepted residual risk changes;
- independent qualified review before any live release;
- updated evidence in `docs/VERIFICATION.md`.

The project currently has one maintainer. `CODEOWNERS` routes review but does
not create independent review. No live security gate may be marked complete
until a qualified reviewer other than the change author records evidence.

## Dependencies

Before adding or upgrading a dependency, document:

- standard-library and operating-system alternatives;
- maintenance activity and release provenance;
- direct and transitive footprint;
- license and compatibility;
- published and reachable vulnerabilities;
- build scripts, network behavior, and CI permissions;
- compromise blast radius and a removal or replacement path.

Record the comparison and decision in the pull request or an ADR. Pin the
selected version, update the dependency-license report, and rerun the license
and vulnerability scanners. No allowlist exception may be added merely to make
CI green.

## Documentation and claims

Use present tense only for behavior proven in the current tree. Label designs,
scaffolds, mocks, dry-run modules, and future architecture explicitly. Never
describe a VPN exit country as physical location, promise anonymity, or claim
production readiness without the named release evidence.

## Review and merge

Maintainers may request smaller commits, additional tests, an ADR, or a fresh
threat-model review. Required checks and review conversations must resolve
before merge. Security-sensitive work remains blocked from live release until
the independent-review and adversarial-round requirements are satisfied.

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
