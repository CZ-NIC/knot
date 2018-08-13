#!/bin/bash
#
# Builds the checked out version in knot-dns-testing OBS repository

set -o errexit -o nounset -o xtrace

force=false

# Read options
while getopts "f" o; do
	case "${o}" in
		f)
			force=true
			;;
		*)
			;;
	esac
done
shift $((OPTIND-1))

# Clean working tree
if [[ $(git status --porcelain | wc -l) -ne 0 ]]; then
    if [ "$force" = false ]; then
        echo "working tree dirty. force clean with '-f'"
        exit 1
    fi
    git clean -dfx
    git reset --hard
fi

# Create tarball
autoreconf -if
./configure
make distcheck AM_DISTCHECK_CONFIGURE_FLAGS="--disable-fastparser"

# Submit to OBS
scripts/make-distrofiles.sh -s
scripts/build-in-obs.sh knot-dns-testing

echo "Check results at https://build.opensuse.org/package/show/home:CZ-NIC:knot-dns-testing/knot"
