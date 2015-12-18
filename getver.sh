#!/bin/sh
awk '/^#define LIBKNOT_VERSION_'$1'/ { print $3 }' src/libknot/version.h | tr -d '"\n'
