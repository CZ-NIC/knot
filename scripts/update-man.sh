#!/bin/bash

pushd ../doc

make man

for f in ./_build/man/*; do
  file=`basename $f`
  echo "Processing '${file}' file..."
  sed -e "s/__VERSION__/@VERSION@/g; s/__DATE__/@RELEASE_DATE@/g" ${f} > ../man/${file}.in
done

popd

