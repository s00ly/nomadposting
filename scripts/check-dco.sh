#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base-commit> <head-commit>" >&2
  exit 2
fi

base=$1
head=$2

git rev-parse --verify "${base}^{commit}" >/dev/null
git rev-parse --verify "${head}^{commit}" >/dev/null

failed=0
checked=0

while IFS= read -r commit; do
  [[ -n "$commit" ]] || continue
  checked=$((checked + 1))

  author_name=$(git show -s --format=%an "$commit")
  author_email=$(git show -s --format=%ae "$commit")
  expected="${author_name} <${author_email}>"
  required=("$expected")
  signoffs=()

  while IFS= read -r trailer; do
    key=${trailer%%:*}
    value=${trailer#*:}
    value=${value#"${value%%[![:space:]]*}"}

    case "${key,,}" in
      co-authored-by)
        required+=("$value")
        ;;
      signed-off-by)
        signoffs+=("$value")
        ;;
    esac
  done < <(git show -s --format=%B "$commit" | git interpret-trailers --parse)

  for identity in "${required[@]}"; do
    matched=0
    for signoff in "${signoffs[@]}"; do
      if [[ "${signoff,,}" == "${identity,,}" ]]; then
        matched=1
        break
      fi
    done

    if [[ $matched -ne 1 ]]; then
      echo "DCO failure: ${commit} needs 'Signed-off-by: ${identity}'" >&2
      failed=1
    fi
  done
done < <(git rev-list --reverse "${base}..${head}")

if [[ $checked -eq 0 ]]; then
  echo "DCO failure: no commits found in ${base}..${head}" >&2
  exit 1
fi

if [[ $failed -ne 0 ]]; then
  exit 1
fi

echo "DCO check passed for ${checked} commit(s)."
