#!/usr/bin/env bash
# Decides whether a change can alter the verdicts of Cross over pkg/witness.
#
#   witness-affected.sh <base> <head>
#
# Prints "true" when a file changed between base and head lies in a package the
# witness suite or subpoena-cross builds from (go list -deps -test, this module
# only), in a file those tests read from outside their package, or in the files
# that run the check. Prints "false" otherwise. Unchanged packages, inputs and
# tooling give the same mutants and the same suite, so the verdicts of the last
# full run still hold; the nightly run in ci.yml checks that they do.
#
# Prints "true" on any doubt: a failed diff or go list must not read as "unchanged".
set -euo pipefail
base=$1
head=$2

# Files the witness tests read from outside pkg/witness (os.ReadFile("../../...")),
# and the files that decide how the check runs.
extra='^(go\.mod|go\.sum|conformance/|docs/witness-event\.schema\.json|\.github/workflows/ci\.yml|\.github/scripts/(witness-affected|cross-shards-cover)\.sh)'

if ! changed=$(git diff --name-only "$base" "$head"); then
	echo "witness-affected: git diff $base $head failed; running the check" >&2
	echo true
	exit 0
fi
root=$(pwd)
# The witness suite with its tests: every file of these packages counts.
# subpoena-cross without its tests: its own tests and testdata do not change
# what it does, so only its other files count.
if ! wdirs=$(go list -deps -test -f '{{if not .Standard}}{{.Dir}}{{end}}' ./pkg/witness/...) ||
	! cdirs=$(go list -deps -f '{{if not .Standard}}{{.Dir}}{{end}}' ./cmd/subpoena-cross); then
	echo "witness-affected: go list failed; running the check" >&2
	echo true
	exit 0
fi
# A prefix match also takes in testdata and any nested package, which can only
# run the check more often, never less.
wprefixes=$(echo "$wdirs" | sed -n "s#^$root/##p" | sort -u)
cprefixes=$(echo "$cdirs" | sed -n "s#^$root/##p" | sort -u)

under() { # under <file> <prefixes>
	local p
	while IFS= read -r p; do
		case "$1" in "$p"/*) return 0 ;; esac
	done <<<"$2"
	return 1
}

hit=""
while IFS= read -r f; do
	[ -n "$f" ] || continue
	if echo "$f" | grep -qE "$extra" || under "$f" "$wprefixes"; then
		hit="$hit $f"
		continue
	fi
	case "$f" in *_test.go | */testdata/*) continue ;; esac
	if under "$f" "$cprefixes"; then
		hit="$hit $f"
	fi
done <<<"$changed"

if [ -n "$hit" ]; then
	echo "witness-affected: changed inputs of Cross over pkg/witness:$hit" >&2
	echo true
else
	echo "witness-affected: no input of Cross over pkg/witness changed" >&2
	echo false
fi
