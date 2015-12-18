#!/bin/sh
echo -n $(awk '/^#define LIBKNOT_VERSION_'$1'/ { print $3 }' src/libknot/version.h | sed -e 's/"//g')
