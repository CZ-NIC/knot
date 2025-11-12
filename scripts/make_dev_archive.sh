#!/bin/bash
# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>
#
# Create a development tarball
#
# This script is used by apkg to generate archive from current sources.
# It must only output valid YAML to stdout!

set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."

# configure Knot DNS in order to create archive
autoreconf -if >&2
./configure >&2
# create archive and parse output for archive name
TARDIR=$(make dist 2>&1 | sed -n 's/tardir=\([^ ]\+\).*/\1/p')
# print created archive name
archive=$(ls -1 $TARDIR.tar.*)
echo "archive: '$archive'"
