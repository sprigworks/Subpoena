#!/usr/bin/env bash
# Checks that n sharded subpoena-cross outputs judged every mutant exactly once.
#
#   cross-shards-cover.sh <n> <output>...
#
# Each output is one shard's stdout. A shard prints "shard k/n: m of T mutant(s)"
# and "shard k/n judged <mutant>" once per mutant it judged alone. The check
# fails if a shard is missing or repeated, if the shards disagree on T, or if the
# judged mutants are not T distinct names: a shard that judged nothing or the
# wrong share must not read as a pass.
set -euo pipefail
n=$1
shift
if [ "$#" -ne "$n" ]; then
	echo "cross-shards-cover: want $n shard outputs, got $#" >&2
	exit 1
fi
shards=$(cat "$@" | sed -n -E "s#^shard ([0-9]+)/$n: [0-9]+ of ([0-9]+) mutant\(s\)\$#\1 \2#p" | sort -n)
if [ "$(echo "$shards" | awk '{print $1}' | tr '\n' ' ')" != "$(seq -s ' ' 1 "$n") " ]; then
	echo "cross-shards-cover: want one summary from each of shards 1..$n, got:" >&2
	echo "$shards" >&2
	exit 1
fi
totals=$(echo "$shards" | awk '{print $2}' | sort -u)
if [ "$(echo "$totals" | wc -l)" -ne 1 ]; then
	echo "cross-shards-cover: shards disagree on the mutant total: $(echo "$totals" | tr '\n' ' ')" >&2
	exit 1
fi
judged=$(cat "$@" | sed -n -E "s#^shard [0-9]+/$n judged ##p")
dups=$(echo "$judged" | sort | uniq -d)
if [ -n "$dups" ]; then
	echo "cross-shards-cover: judged by more than one shard:" >&2
	echo "$dups" >&2
	exit 1
fi
count=$(echo "$judged" | grep -c . || true)
if [ "$count" -ne "$totals" ]; then
	echo "cross-shards-cover: $n shards judged $count distinct mutants of $totals" >&2
	exit 1
fi
echo "cross-shards-cover: $n shards judged all $totals mutants, each once"
