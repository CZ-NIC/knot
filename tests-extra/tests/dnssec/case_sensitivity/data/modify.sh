#!/bin/sh
#
# Perform in-place modification of zone file using given script (awk).
#

usage()
{
	echo "usage: $0 <zone-file> <script>" >&2
}

if [ $# -ne 2 ]; then
	usage
	exit 1
fi

zonefile=$1
script=$2

#
# Extract count of expected changes
#

add=0
remove=0
for change in $(grep -o -m1 'expected-changes .*' "$script" | sed 's/\s\+/\t/g'); do
	case "$change" in
	+*) add=${change#?} ;;
	-*) remove=${change#?} ;;
	esac
done

if [ $add -le 0 -a $remove -le 0 ]; then
	echo "Marker with expected-changes is invalid." >&2
	exit 1
fi

#
# Update the zone file and verify number of changes
#

tmp=$(mktemp)

gawk -f "$script" "$zonefile" > "$tmp"

update_result=$(diff -wu "$zonefile" "$tmp" | gawk '
	BEGIN { add = 0; remove = 0 }
	NR <= 2 { next } # diff header
	$1 ~ /^+/ { add += 1 }
	$1 ~ /^-/ { remove += 1 }
	END { print add, remove }
')

if [ "$update_result" != "$add $remove" ]; then
	echo "The number of performed changes is different than expected." >&2
	echo "$tmp" >&2
	exit 1
fi

# cat "$tmp" && rm "$tmp"
mv -f "$tmp" "$zonefile"
