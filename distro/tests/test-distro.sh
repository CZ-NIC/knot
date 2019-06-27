#!/bin/bash -x

# ./test-distro.sh {obs_repo} {distro}
# Example usage: ./test-distro.sh knot-dns-devel debian9

pkgtestdir="$(dirname ${0})"
repofile="$pkgtestdir/repos.yaml"

repo=$1
distro=$2

# Select repos
echo -e "repos:\n  - $repo" > $repofile

pushd "$pkgtestdir/$distro"
vagrant destroy -f &>/dev/null
vagrant up
ret=$?
vagrant destroy -f &>/dev/null
popd
exit $ret
