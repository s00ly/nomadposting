# NomadPosting Governance

This policy describes how decisions are made in the NomadPosting repository.
It does not weaken the license, security policy, or release gates.

## Current structure

NomadPosting currently has one active maintainer. That is a bus-factor and
independent-review limitation, not a committee. The current maintainer is
listed in [MAINTAINERS.md](MAINTAINERS.md).

The roles are:

- **Contributor:** submits issues, reviews, tests, documentation, or signed-off
  code.
- **Reviewer:** provides evidence-backed review in an area of demonstrated
  competence. Reviewers do not receive merge or security-advisory access by
  default.
- **Maintainer:** triages work, protects repository scope, merges changes,
  administers releases, and applies this governance policy.
- **Security maintainer:** can access private advisories, coordinate embargoed
  fixes, revoke a release, and restart adversarial verification.

## Decision process

Routine decisions are made in public issues and pull requests. Maintainers
should seek rough consensus, name material objections, and record why an option
was chosen. The active maintainer is the tie-breaker while the project has only
one maintainer.

An ADR is required for changes to:

- supported accounts, platforms, or public product scope;
- authentication, signing, secret custody, network isolation, or egress policy;
- retention, logging, recovery, or ambiguous-result handling;
- release gates or accepted residual risk;
- project license, contribution terms, or a material dependency.

Security and privacy claims require reproducible evidence. Popularity,
perception scores, and a successful build are not substitutes.

## Merge authority

Maintainers may merge only when required checks pass, review conversations are
resolved, DCO sign-offs are valid, and the change is within documented scope.
An administrator bypass does not turn a failed check into acceptable evidence.

Security-sensitive changes require qualified review independent of the change
author before they can close a live release gate. Until the project has a
second qualified reviewer, such changes may be merged as disabled or dry-run
scaffolding only when they remain fail closed and are described truthfully.

## Maintainer selection

A contributor may be nominated as a maintainer after demonstrating sustained,
constructive work across at least three substantive contributions over at least
90 days. Evidence should include:

- sound judgment inside the security and anti-evasion boundaries;
- accurate review and documentation;
- timely handling of feedback and conflicts;
- DCO compliance and careful secret handling;
- no unresolved pattern of bypassing release controls.

The active maintainer records the nomination in a public issue, allows at least
seven days for objections, resolves material concerns, and updates
`MAINTAINERS.md` and `CODEOWNERS` in a reviewed pull request.

## Inactivity and removal

A maintainer may mark themselves inactive at any time. A maintainer who has not
participated for 90 days should be asked privately whether they intend to
remain active. Inactivity alone is not misconduct.

Access may be suspended immediately when credentials, advisories, releases, or
users are at risk. Permanent removal requires a written record of the reason,
an opportunity to respond when safe, and review by every other unconflicted
active maintainer. With only one maintainer, an independent trusted reviewer
should examine any contested removal before it is finalized.

## Conflicts of interest

Reviewers and maintainers disclose financial, employment, vendor, or personal
interests that could reasonably affect a decision. A conflicted person should
not be the sole approver for dependency selection, vendor onboarding,
vulnerability handling, or enforcement involving that interest.

## Security authority

Security advisory access is limited to active security maintainers and invited
specialists who need the information. The security maintainer may stop a
release, revoke compromised artifacts, rotate credentials, coordinate private
fixes, and reset required adversarial rounds.

Private vulnerability information is published only through coordinated
disclosure. A fixed network-served version must make its corresponding source
available no later than user-facing deployment under the AGPL.

## License and contribution terms

NomadPosting uses `AGPL-3.0-or-later`, DCO 1.1, contributor-retained copyright,
and no CLA. The DCO confirms provenance and the right to submit. It does not
assign copyright or give the project unilateral proprietary relicensing power.

A license change requires:

1. a public ADR explaining user-freedom, compatibility, contributor, patent,
   and sustainability effects;
2. approval from every copyright holder whose permission is legally required;
3. a complete dependency-license review;
4. a migration plan that does not misstate or revoke rights already granted.

## Succession

Maintainers should keep recovery access, release procedures, and security
contacts current without storing secrets in the repository. If the sole
maintainer can no longer serve, they should nominate a successor through a
public governance issue and transfer sensitive access privately after identity
verification.

If no maintainer remains, the repository is unmaintained. No contributor may
imply official maintainer or release authority merely by publishing a fork.
