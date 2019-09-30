#!/usr/bin/env sh

version=`ls knot-*.tar.xz | sed "s/knot-\(.*\).tar.xz/\1/" | sort -r | head -n 1`
sed -e "s/__VERSION__/${version}/g" distro/rpm/knot.spec > knot.spec
find distro/rpm/ ! -name knot.spec -exec cp -t ./ {} + 2> /dev/null
cp knot-${version}.tar.xz knot_${version}.orig.tar.xz
exit 0

