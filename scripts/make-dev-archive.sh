#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Create a development tarball
set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."

# configure Knot DNS in order to create archive
autoreconf -if
./configure
# create archive and parse output for archive name
TARDIR=$(make dist 2>&1 | sed -n 's/tardir=\([^ ]\+\).*/\1/p')
# print created archive name
ls -1 $TARDIR.tar.*
