# Contributing to NomadPosting

NomadPosting welcomes design reviews, tests, documentation, and code that
strengthen its stated privacy and safety boundaries. Read the
[threat model](docs/THREAT_MODEL.md), [security policy](docs/SECURITY.md), and
[verification record](docs/VERIFICATION.md) before changing behavior.

## Contribution terms

Contributions are accepted under the same
[AGPL-3.0-or-later](LICENSE) terms as the project. The project uses the
[Developer Certificate of Origin 1.1](DCO) and does not require a Contributor
License Agreement or copyright assignment.

Every commit must include a `Signed-off-by:` trailer matching the commit
author. Add it automatically with:

```sh
git commit -s
```

The sign-off certifies the statements in the DCO. It is not a decorative
footer. The name and email in the trailer become part of the permanent public
Git history. Use an address you are authorized to publish.

If a commit is missing its sign-off, amend or rebase that commit and update the
pull-request branch. Do not add a later commit that claims to sign an earlier
one. Each co-author must provide their own sign-off.

The `dco / signoff` pull-request check rejects unsigned commits. Repository
administrators must configure that check as required in the default-branch
ruleset; the workflow alone cannot prevent an administrator from bypassing it.

## Change standard

A pull request must:

- explain the behavior and trust-boundary impact;
- include tests or reproducible evidence proportional to the risk;
- update threat-model, security, deployment, or verification documents when
  their claims change;
- keep dependencies pinned and document new dependency alternatives, license,
  maintenance, vulnerabilities, transitive footprint, and network behavior;
- pass formatting, tests, static analysis, vulnerability, dependency-license,
  and DCO checks without bypasses.

Medium-or-higher security or privacy findings reopen the affected adversarial
rounds. Do not use expected-failure markers, swallowed errors, hardcoded test
bypasses, or verification-suppression flags.

## Security reports

Do not disclose exploitable details in a public issue. Follow the private
reporting instructions in [docs/SECURITY.md](docs/SECURITY.md).
