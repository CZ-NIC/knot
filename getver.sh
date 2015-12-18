#!/bin/sh
awk '/^#define LIBKNOT_VERSION_'$1'/ { printf "%s", $3 }' src/libknot/version.h | sed -e 's/"//g'
