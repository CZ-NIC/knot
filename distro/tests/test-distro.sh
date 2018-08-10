#!/bin/bash -x

# ./test-distro.sh {devel|latest} {distro}
# Example usage: ./test-distro.sh devel debian9

distro=$2
repo=$1

# Select repos
case "$repo" in
	devel)
		echo -e 'repos:\n  - knot-dns-devel' > repos.yaml
		;;
	testing)
		echo -e 'repos:\n  - knot-dns-testing' > repos.yaml
        ;;
	latest)
		echo -e 'repos:\n  - knot-dns-latest' > repos.yaml
		;;
	*)
		echo "Unknown repo, choose devel|latest"
		exit 1
		;;
esac

cd "$distro"
vagrant destroy &>/dev/null
vagrant up
ret=$?
vagrant destroy &>/dev/null
exit $ret

