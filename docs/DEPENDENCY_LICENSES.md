# Dependency License Review

Date: 2026-07-15

NomadPosting is licensed under `AGPL-3.0-or-later`. This review covers every Go
module used by `./...` at the versions pinned in `go.mod` and `go.sum`.
Permitted dependency licenses are `Apache-2.0`, `BSD-2-Clause`,
`BSD-3-Clause`, and `MIT`; each is compatible with GPLv3-family distribution.
The project license itself is also allowed as `AGPL-3.0` because license-text
classifiers cannot encode the separate "or later" grant stated in the README.
Compatibility was cross-checked against the GNU project's
[license list](https://www.gnu.org/licenses/license-list.html).

## Automated evidence

Run:

```sh
bash ./scripts/check-licenses.sh
```

The script pins `google/go-licenses` at `v2.0.1` and rejects every unapproved or
unknown detected license. There are no ignored modules or license exceptions.

## Reviewed modules

| License | Modules |
|---|---|
| Apache-2.0 | `github.com/google/go-tpm v0.9.8` |
| BSD-2-Clause | `github.com/go-webauthn/x v0.2.6` includes the `revoke` package under this license |
| BSD-3-Clause | `github.com/go-webauthn/webauthn v0.17.4`, the remaining used packages from `github.com/go-webauthn/x v0.2.6`, `github.com/google/uuid v1.6.0`, `github.com/remyoudompheng/bigfft` at `24d4a6f8daec`, `golang.org/x/crypto v0.52.0`, `golang.org/x/sys v0.45.0`, `modernc.org/libc v1.73.4`, `modernc.org/mathutil v1.7.1`, `modernc.org/memory v1.11.0`, `modernc.org/sqlite v1.53.0` |
| MIT | `github.com/dustin/go-humanize v1.0.1`, `github.com/fxamacker/cbor/v2 v2.9.2`, `github.com/go-viper/mapstructure/v2 v2.5.0`, `github.com/golang-jwt/jwt/v5 v5.3.1`, `github.com/mattn/go-isatty v0.0.20`, `github.com/ncruces/go-strftime v1.0.0`, `github.com/philhofer/fwd v1.2.0`, `github.com/tinylib/msgp v1.6.4`, `github.com/x448/float16 v0.8.4` |

`modernc.org/libc` also carries notices for incorporated Go, musl, go-netdb,
and NixOS/nixpkgs material under BSD-style, MIT, or public-domain terms. The
SQLite material included by `modernc.org/sqlite` is public domain. No reviewed
dependency imposes a copyleft term that conflicts with AGPL distribution.

Any dependency or scanner update requires a fresh report and manual review of
new, changed, unknown, or multi-license results.

## Scanner decision record

The scanner is a CI-only build tool. It is not linked into NomadPosting or its
release artifacts.

| Option | Coverage | Reproducibility | Supply-chain exposure | Score |
|---|---:|---:|---:|---:|
| [`google/go-licenses v2.0.1`](https://github.com/google/go-licenses) | 4/5 | 4/5 | 3/5 | **11/15** |
| GitHub enterprise license policy | 4/5 | 2/5 | 4/5 | 10/15 |
| Manual review only | 2/5 | 2/5 | 5/5 | 9/15 |
| New custom classifier | 2/5 | 3/5 | 4/5 | 9/15 |

Decision: use `google/go-licenses v2.0.1` with no exceptions. It provides
locally reproducible transitive analysis without requiring an enterprise
GitHub feature. Version 1.6.0 was rejected after its binary vulnerability scan
found 17 reachable vulnerabilities, including legacy `go-git` path-traversal
and remote-code-execution advisories. The selected v2.0.1 binary scan found zero
reachable vulnerabilities; nine module-level advisories were present only in
code paths the binary does not call. A custom classifier would create more
security and maintenance risk than it removes.

Blast radius: the scanner executes third-party Go code during CI and can read
the checked-out repository and make network requests while Go downloads its
pinned modules. Controls are an exact released version, public Go checksum
verification, a read-only workflow token, disabled checkout credentials, no CI
secrets, a strict license allowlist, and a five-minute step within the existing
twenty-minute job. Replace or remove the scanner if it becomes unmaintained or
its binary vulnerability scan gains a reachable finding.
