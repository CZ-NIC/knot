#!/bin/bash
#
# The script
# 1. Generates manual pages from Sphinx.
# 2. Removes bold from definition lists (bug in Sphinx).
#    https://github.com/sphinx-doc/sphinx/issues/1498
# 3. Replaces version placeholders
#

pushd "$(dirname "$(readlink -e "$0")")/../doc"

make man

for f in ./_build/man/*; do
  file=`basename $f`
  echo "Processing '${file}' file..."
  sed -e '/^.TP$/{n;s/^.B //}' \
      -e "s/__VERSION__/@VERSION@/g; s/__DATE__/@RELEASE_DATE@/g" \
      "${f}" > "../man/${file}.in"
done

popd
