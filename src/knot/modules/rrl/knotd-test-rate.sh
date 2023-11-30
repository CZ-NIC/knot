#!/bin/bash

# ./test-rate.sh SERVER_ADDRESS INTERVAL_BETWEEN_QUERIES

addr=${1-localhost}
limit_rate=:
if [[ -n "$2" ]]; then
	limit_rate="sleep $2"
fi

total=0
passed=0

trap 'echo; echo "$passed/$total"' EXIT

while true; do
	if ! kdig -p5353 "@$addr" localhost 2>&1 | grep -q truncated; then
		echo -n "+"
		((passed++))
	else
		echo -n "-"
	fi
	((total++))
	$limit_rate
done
