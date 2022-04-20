#!/bin/sh

WORKDIR=$(mktemp -d)
trap 'cd /; rm -rf "$WORKDIR"' EXIT

( cd $WORKDIR && dnssec-keygen -a 13 tc.test; )

dnssec-signzone -S -P -d "$WORKDIR" -K "$WORKDIR" \
	-o tc.test -f tc.test.zone tc.test.zone.unsigned
