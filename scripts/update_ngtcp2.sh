#!/bin/bash

set -ueo pipefail

ROOT_PATH="$(dirname "$(realpath "$0")")/../src/contrib/libngtcp2/ngtcp2"
NGTCP2_GIT="https://github.com/ngtcp2/ngtcp2"

if [ $# != 1 ]; then
	printf 'expected single arg - git tag name to which to upgrade\n'
	exit 1
fi

clonedir="$(mktemp -d)"
trap 'rm -rf "$clonedir"; printf "error encountered - aborting\n"' ERR

cur_version=v"$(sed -En 's/^.*NGTCP2_VERSION[^"]*"([0-9.]+)"/\1/p' "${ROOT_PATH}/version.h")"

git clone --branch="$1" "$NGTCP2_GIT" "${clonedir}/ngtcp2" 2>/dev/null

cd "${clonedir}/ngtcp2"
git diff --name-only --diff-filter=A "$cur_version" "$1"  | xargs -r realpath >../added
git diff --name-only --diff-filter=D "$cur_version" "$1"  | xargs -r realpath >../deleted
git diff --name-only --diff-filter=ad "$cur_version" "$1" | xargs -r realpath >../changed

# generate new version.h
autoreconf -if >/dev/null 2>&1
./configure --enable-lib-only --with-gnutls >/dev/null 2>&1
cp ./lib/includes/ngtcp2/version.h "${ROOT_PATH}"

cd "$ROOT_PATH"

# delete files deleted in new version
while IFS=$'\n' read -r line; do
	find . -type f -name "$(basename "$line")" | xargs -r rm
done <"${clonedir}/deleted"

# update changed files
find . -type f | while IFS=$'\n' read -r line; do
	base="$(basename "$line")"
	match="$(grep -m1 "$base" "${clonedir}/changed" || true)"
	if [ -n "$match" ]; then
		cp "$match" "$line"
	fi
done

# ngtcp2_crypto.h is the only non-unique filename, so we deal with it separately
# ugly - I'm aware ;p
cp "${clonedir}/ngtcp2/lib/ngtcp2_crypto.h" ./lib/ngtcp2_crypto.h
cp "${clonedir}/ngtcp2/crypto/includes/ngtcp2/ngtcp2_crypto.h" ./ngtcp2_crypto.h

newfiles="$(wc -l "${clonedir}/added" | cut -d' ' -f1)"
if [ "$newfiles" -gt 0 ]; then
	printf "%s new file(s) were added between %s and %s; add these manually if desired:\n" \
		"$newfiles" "$cur_version" "$1"
	cut -d'/' -f'5-' "${clonedir}/added" | xargs -r printf "\t%s\n"
fi

rm -rf "$clonedir"
