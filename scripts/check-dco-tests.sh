#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
checker="${script_dir}/check-dco.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

git -C "$fixture" init --quiet
git -C "$fixture" config user.name "Test Author"
git -C "$fixture" config user.email "author@example.invalid"
git -C "$fixture" config core.autocrlf false

run_check() {
  (cd "$fixture" && bash "$checker" "$@")
}

printf 'root\n' >"${fixture}/fixture.txt"
git -C "$fixture" add fixture.txt
git -C "$fixture" commit --quiet -m "Root fixture"
base=$(git -C "$fixture" rev-parse HEAD)

printf 'before adoption\n' >>"${fixture}/fixture.txt"
git -C "$fixture" add fixture.txt
git -C "$fixture" commit --quiet -m "Unsigned pre-adoption fixture"
pre_adoption=$(git -C "$fixture" rev-parse HEAD)

if run_check "$base" "$pre_adoption" >/dev/null 2>&1; then
  echo "DCO test failure: a range without DCO unexpectedly passed" >&2
  exit 1
fi

cp "${script_dir}/../DCO" "${fixture}/DCO"
git -C "$fixture" add DCO
git -C "$fixture" commit --quiet --signoff -m "Adopt DCO"
adoption=$(git -C "$fixture" rev-parse HEAD)

run_check "$base" "$adoption" >/dev/null

printf 'signed\n' >>"${fixture}/fixture.txt"
git -C "$fixture" add fixture.txt
git -C "$fixture" commit --quiet --signoff -m "Signed fixture"
signed=$(git -C "$fixture" rev-parse HEAD)

run_check "$adoption" "$signed" >/dev/null

printf 'coauthored\n' >>"${fixture}/fixture.txt"
git -C "$fixture" add fixture.txt
git -C "$fixture" commit --quiet --signoff \
  -m "Unsigned co-author fixture" \
  -m "Co-authored-by: Co Author <coauthor@example.invalid>"
unsigned_coauthor=$(git -C "$fixture" rev-parse HEAD)

if run_check "$signed" "$unsigned_coauthor" >/dev/null 2>&1; then
  echo "DCO test failure: an unsigned co-author unexpectedly passed" >&2
  exit 1
fi

git -C "$fixture" commit --quiet --amend \
  -m "Signed co-author fixture" \
  -m $'Signed-off-by: Test Author <author@example.invalid>\nCo-authored-by: Co Author <coauthor@example.invalid>\nSigned-off-by: Co Author <coauthor@example.invalid>'
signed_coauthor=$(git -C "$fixture" rev-parse HEAD)

run_check "$signed" "$signed_coauthor" >/dev/null

printf 'unsigned after adoption\n' >>"${fixture}/fixture.txt"
git -C "$fixture" add fixture.txt
git -C "$fixture" commit --quiet -m "Unsigned post-adoption fixture"
unsigned=$(git -C "$fixture" rev-parse HEAD)

if run_check "$signed_coauthor" "$unsigned" >/dev/null 2>&1; then
  echo "DCO test failure: an unsigned post-adoption commit unexpectedly passed" >&2
  exit 1
fi

if run_check "$signed" "$signed" >/dev/null 2>&1; then
  echo "DCO test failure: an empty range unexpectedly passed" >&2
  exit 1
fi

echo "DCO self-tests passed."
