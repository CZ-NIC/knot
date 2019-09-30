#!/usr/bin/env sh

version=`ls knot*.tar.xz | sed "s/knot-\(.*\).tar.xz/\1/"`
sed -e "s/__VERSION__/2.8.4/g" distro/rpm/knot.spec > $1
find distro/rpm/ ! -name knot.spec -exec cp -t ./ {} + 2> /dev/null 
exit 0

