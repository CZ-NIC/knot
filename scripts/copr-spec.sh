#!/usr/bin/env sh

version=`ls knot*.tar.xz | sed "s/knot-\(.*\).tar.xz/\1/" | sort -r | head -n 1`
sed -e "s/__VERSION__/${version}/g" distro/rpm/knot.spec > ~/rpmbuild/SPECS/knot.spec
find distro/rpm/ ! -name knot.spec -exec cp -t ~/rpmbuild/SOURCES/ {} + 2> /dev/null 
ln -sr knot-${version}.tar.xz ~/rpmbuild/SOURCES/knot_${version}.orig.tar.xz
exit 0

