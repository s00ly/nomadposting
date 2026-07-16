## Summary

Describe the behavior changed and why.

## Linked decision

Link the issue, release gate, or ADR. Explain why this belongs in the current
scope.

## Trust-boundary impact

Name affected credentials, network paths, stored data, user claims, and failure
states. Write `None` only after checking the threat model.

## Dependency decision

For each added or upgraded dependency, compare alternatives, maintenance,
license, vulnerabilities, transitive footprint, network behavior, CI access,
and compromise blast radius. Write `None` if no dependency changed.

## Verification

List exact commands, environments, artifacts, and results.

## Release effect

State which release gates remain open. Do not claim live or production
readiness unless every required artifact is linked.

## Checklist

- [ ] Tests and documentation match the changed behavior.
- [ ] No secret, private key, token, or exploitable detail is included.
- [ ] New dependencies include alternatives, license, security, and blast-radius review.
- [ ] Security-sensitive changes name the threat, trust boundary, and negative tests.
- [ ] Medium-or-higher findings reopened the affected adversarial rounds.
- [ ] User-facing privacy, location, and readiness claims are evidence-backed.
- [ ] Relevant threat model, security policy, ADR, deployment, and verification records are updated.
- [ ] Every commit has the author-matching `Signed-off-by:` trailer required by the DCO.
