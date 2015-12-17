#!/bin/sh
echo -n $(awk '/^#define LIBKNOT_'$1'_VERSION/ { print $3 }' src/libknot/version.h | sed -e 's/"//g')
