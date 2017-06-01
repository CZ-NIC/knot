#!/bin/bash

if [ -z "$1" -o "${1:0:1}" == "-" ]; then
  echo "Usage: $0 <zone name> [<resolver IP:port>]" >&2
  echo "" >&2
  echo "This script generates part of Knot DNS configuration regarding KSK submittion" >&2
  echo "for automatic KSK rollover. It gathers IP addresses of all parent zone's NS servers." >&2
  echo "You shall specify your zone as the first parameter and facultatively your resolver's" >&2
  echo "address and port." >&2
  exit 1
fi

ZONE="$1."
ZONE="${ZONE/%../.}"
if [ -z "$2" ]; then
  RESOLVER=
else
  RESOLVER="@$2"
fi
if [ -n "$KDIG" -a -e "$KDIG" ]; then
  echo "all ok" > /dev/null
else
  if KDIG=$(which kdig); then
    echo "also ok" > /dev/null
  else
    echo "Error: can't find kdig program. Please specify kdig location in KDIG variable." >&2
    exit 10
  fi
fi

# step 1: parent zone
PARENT_ZONE=$(echo "$ZONE" | sed 's/^[^.]*\.//')

# step 2: any parent zone's NS
PARENT_NS=$("$KDIG" $RESOLVER -t NS "$PARENT_ZONE" | grep -A 1 'ANSWER SECTION' | awk '{ if (NF == 5) print $5; }')
if [ -z "$PARENT_NS" ]; then
  echo "Error: can't resolve any NS record for zone $PARENT_ZONE" >&2
  exit 8
fi

# step 3: all parent zone's NSs
ALL_NS=$("$KDIG" "@$PARENT_NS" -t NS "$PARENT_ZONE" | awk '{ if (NF == 5 && $4 == "NS" && $1 == "'"$PARENT_ZONE"'") print $5; }' | sort)
if [ -z "$ALL_NS" ]; then
  echo "Error while gathering all parent zone's NSs." >&2
  exit 20
fi

# step 4: all parent zone NSs' IP addresses and generate conf
for NS in $ALL_NS; do
  NSID="${NS//./_}"
  NSIP=$( ("$KDIG" $RESOLVER -t A "$NS"; "$KDIG" $RESOLVER -t AAAA "$NS" ) | awk '{ if (NF == 5 && ($4 == "A" || $4 == "AAAA") && $1 == "'"$NS"'") print $5; }' | tr '\n' ' ')
  case $(echo "$NSIP" | wc -w) in
  0)
    echo "Error: can't resolve neither A nor AAAA record for parent zone's NS $NS" >&2
    exit 6
    ;;
  1)
    ADDRS=${NSIP/% /}
    ;;
  *)
    ADDRS="[ ${NSIP/% /} ]"
    ;;
  esac
  echo "remote:"
  echo "  - id: $NSID"
  echo "    address: $ADDRS"
  echo ""
done

echo "# add this to policy section"
echo -n "    ksk-submittion-check: [ "
for NS in $ALL_NS; do
  NSID="${NS//./_}"
  echo -n "$NSID "
done
echo "]"

exit 0
