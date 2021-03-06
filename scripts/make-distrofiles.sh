#!/bin/bash -e

# Run with -s to include *.symbols files.

package=knot
withsymbols=false

while getopts "s" o; do
	case "${o}" in
		s)
			withsymbols=true
			;;
		*)
			;;
	esac
done
shift $((OPTIND-1))


cd "$(git rev-parse --show-toplevel)"
version=$(ls ${package}*.tar.xz | sed "s/${package}-\(.*\).tar.xz/\1/")

# Check version for invalid characters
if [[ $(echo "${version}" | grep '^[[:alnum:].]$') -ne 0 ]]; then
	echo "Invalid version number: may contain only alphanumeric characters and dots"
	exit 1
fi

# Fill in VERSION field in distribution specific files
files="distro/pkg/rpm/${package}.spec distro/pkg/deb/changelog distro/pkg/arch/PKGBUILD"
for file in ${files}; do
	sed -i "s/{{ version }}/${version}/g" "${file}"
	sed -i "s/{{ release }}/1/g" "${file}"
done

# Rename archive to debian format
pkgname="${package}-${version}"
debname="${package}_${version}.orig"
ln -s "${pkgname}.tar.xz" "${debname}.tar.xz"

# Prepare clean debian-specific directory
tar -xf "${debname}.tar.xz"
pushd "${pkgname}" > /dev/null
cp -arL ../distro/pkg/deb debian

# Optionally remove symbols file
if [ "$withsymbols" = false ]; then
	rm -f debian/*.symbols
fi

# Create debian archive and dsc
dpkg-source -b .
popd > /dev/null
