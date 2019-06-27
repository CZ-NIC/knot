#!/bin/bash -x

# ./test-distro.sh {devel|latest} {distro}
# Example usage: ./test-distro.sh devel debian9

pkgtestdir="$(dirname ${0})"
repofile="$pkgtestdir/repos.yaml"

distro=$2
repo=$1

# Select repos
case "$repo" in
	devel)
		echo -e 'repos:\n  - knot-dns-devel' > $repofile
		;;
	testing)
		echo -e 'repos:\n  - knot-dns-testing' > $repofile
        ;;
	latest)
		echo -e 'repos:\n  - knot-dns-latest' > $repofile
		;;
	*)
		echo "Unknown repo, choose devel|latest|testing"
		exit 1
		;;
esac

pushd "$pkgtestdir/$distro"
vagrant destroy -f &>/dev/null
vagrant up
ret=$?
vagrant destroy -f &>/dev/null
popd
exit $ret
