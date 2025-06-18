#!/usr/bin/env bash
# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>

# This package is needed on Debian derived ditributions: libglib2.0-bin

# This is an example script demonstrating Knot DNS's interface for external zone update verification.
#
# Expected configuration:
#
# server:
#     ...
#     dbus-event: external-verify
#
# external:
#   - id: extval_example
#     dump-removals: %s.zonediff
#     dump-additions: %s.zonediff
#
# zone:
#     ...
#     external-validation: extval_example

ZONEFILE=/var/lib/knot/%szonediff
MAX_NS_DIFF=1000 # maximum allowed changed NS records

function validate() {
    DIFF="$1"
    NSCOUNT=$(awk '{ if ($3 == "NS") nscount++; } END { print nscount; }' "$DIFF")
    if [[ "$?" -gt 0 ]]; then
        return 1
    fi
    if [[ "$NSCOUNT" -gt "$MAX_NS_DIFF" ]]; then
        echo "...failed"
        # TODO send yourself an e-mail here
        return 1
    fi
    echo "...passed"
}

gdbus monitor --system --dest cz.nic.knotd --object-path /cz/nic/knotd \
    | while read dest event args; do
        if [[ "$dest" =~ ^/cz/nic/knotd:* && "$event" =~ \.external_verify$ ]]; then
            ZONE=$(echo "$args" | cut -d "'" -f 2)
            ZONEDIFF=${ZONEFILE//%s/$ZONE}
            echo "Validating diff of zone '$ZONE' at $ZONEDIFF"
            if validate "$ZONEDIFF"; then
                knotc zone-commit "$ZONE"
            else
                knotc zone-abort "$ZONE"
            fi
        fi
done
