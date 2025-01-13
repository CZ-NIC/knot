#!/usr/bin/env bash

# Set database to event listening and then watch DB 0 for changes (SET action)

keydb-cli "$@" <<-EOF
        CONFIG SET notify-keyspace-events KEA
        PSUBSCRIBE '__keyevent@0__:set'
EOF