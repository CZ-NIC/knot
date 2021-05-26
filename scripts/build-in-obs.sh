#!/bin/bash -e

# Example usage:
# 1. place tarball to be released in git root dir
# 2. scripts/make-distrofiles.sh -s
# 3. scripts/build-in-obs.sh knot-dns-latest

project=home:CZ-NIC:$1
package=knot

if ! [[ "$1" == *-devel || "$1" == *-testing ]]; then
	read -p "Pushing to '$project', are you sure? [y/N]: " yn
	case $yn in
		[Yy]* )
            ;;
		* )
            exit 1
	esac
fi

osc co "${project}" "${package}"
pushd "${project}/${package}"
osc del * ||:
cp -L ../../*.tar.xz ../../*.dsc ./
cp -rL ../../distro/pkg/rpm/* ./
cp -rL ../../distro/pkg/arch/* ./
osc addremove
osc ci -n
popd
