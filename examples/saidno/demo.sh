#!/usr/bin/env bash
# Runs the same gateway three ways and prints what each kind of check says.
# Exits non-zero if any check doesn't come out the way the README says, so CI
# keeps the demo honest. Needs Go 1.25+ on Linux, and no privileges.
set -u
if [ "$(uname -s)" != Linux ]; then
	echo 'This demo needs Linux: its witness reads /proc.' >&2
	exit 1
fi
cd "$(dirname "$0")/../.."
pkg=./examples/saidno
bad=0

# check <label> <want PASS|FAIL> <tags> <test pattern> [text the failure must contain]
check() {
	local label=$1 want=$2 tags=$3 run=$4 expect=${5:-} out code got detail='' ok=1
	out=$(go test -v -count=1 -tags "$tags" -run "$run" "$pkg" 2>&1)
	code=$?
	got=PASS
	[ "$code" -eq 0 ] || got=FAIL
	# A real result only: a named test ran and ended the expected way, for the
	# expected reason.
	grep -qE "^--- $got: $run" <<<"$out" || ok=0
	grep -q '^panic:' <<<"$out" && ok=0
	[ "$got" = "$want" ] || ok=0
	if [ -n "$expect" ]; then
		grep -qF "$expect" <<<"$out" || ok=0
		case $expect in
		Inconclusive*) detail='Inconclusive: capture failed, so nothing is proven' ;;
		*) detail="the witness saw: $expect" ;;
		esac
	fi
	printf '  %-40s %s  %s\n' "$label" "$got" "$detail"
	if [ "$ok" -ne 1 ]; then
		echo "  unexpected: wanted $want from $run" >&2
		echo "$out" >&2
		bad=1
	fi
}

echo 'The rule: a denied agent gets a 403, and its tool never runs.'
echo
echo '1. Original code: authorize, then run.'
check 'Ordinary tests (status, log, spans)' PASS '' 'TestOrdinary'
check 'Subpoena (independent witness)' PASS '' 'TestWitness'
echo
echo '2. Refactored: check the tool works first, so a broken one fails fast.'
echo '   It still answers 403 and logs the denial. The tool has already run.'
check 'Ordinary tests (status, log, spans)' PASS refactored 'TestOrdinary'
check 'Subpoena (independent witness)' FAIL refactored 'TestWitnessDenied' 'tool --version'
echo
echo '3. Same bug, and the witness loses its view of /proc.'
check 'Reading the witness, no health check' PASS 'refactored blind' 'TestBlindNoHealthCheck'
check 'Subpoena (checks capture health)' FAIL 'refactored blind' 'TestBlindHarnessCheck' 'Inconclusive: witness:'
echo
if [ "$bad" -ne 0 ]; then
	echo 'The demo did not come out as documented.' >&2
	exit 1
fi
echo 'See examples/saidno/README.md, and diff run_original.go run_refactored.go.'
