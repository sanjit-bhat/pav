#!/bin/bash
# Reproduces §12 of etc/worklog.md: which epoch-commit shapes survive a crash on
# a single-version store, and which do not.
#
#   cd etc/bench/diskbench && go build -o crashtest/crashtest ./crashtest
#   ./crashtest/run.sh
#
# each case seeds a tree, applies one more epoch, SIGKILLs the writer at a
# chosen point, then reopens and re-proves every committed label against
# whatever HEAD survived. "OK" means the store is consistent with its own HEAD.
set -u
CT=$(dirname "$0")/crashtest
D=${TMPDIR:-/var/tmp}/crashtest-run
N=${N:-20000}

run() {
	local name=$1 commit=$2 crash=$3 want=$4
	rm -rf "$D"
	"$CT" -dir "$D" -phase seed -batch "$N" >/dev/null 2>&1
	# bash prints a "Killed" notice for each of these; that is the SIGKILL
	# landing, which is the point of the exercise.
	"$CT" -dir "$D" -phase epoch -which 1 -batch "$N" -commit "$commit" -crash "$crash" >/dev/null 2>&1
	local out
	out=$("$CT" -dir "$D" -phase verify -batch "$N" -epochs 3 2>/dev/null | tail -1)
	local got=FAIL
	case "$out" in OK*) got=OK ;; esac
	if [ "$got" = "$want" ]; then
		printf '%-46s %-4s (expected)  %s\n' "$name" "$got" "$out"
	else
		printf '%-46s %-4s WRONG, wanted %s: %s\n' "$name" "$got" "$want" "$out"
		FAILED=1
	fi
	rm -rf "$D"
}

FAILED=0
echo "epoch commit shapes under kill -9, ${N} leaves per epoch, Pebble:"
echo
# design A's node keys are mutable, so epoch e+1's records overwrite the ones
# epoch e's digest points through. on a single-version store that makes
# "records, then HEAD" unsafe -- which is the point of the first case.
run "records then HEAD, crash after records"   headlast mid   FAIL
run "records then HEAD, no crash"              headlast ""    OK
run "one atomic batch, crash before commit"    atomic   mid   OK
run "one atomic batch, crash right after"      atomic   after OK
run "one atomic batch, no crash"               atomic   ""    OK
echo
if [ "$FAILED" = 0 ]; then
	echo "all cases behaved as §12 records"
else
	echo "a case did not behave as §12 records"
	exit 1
fi
