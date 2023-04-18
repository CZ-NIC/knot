#!/bin/sh

set -e

KEYMGR=${KEYMGR:-keymgr}

if basename $(pwd) | grep -q '^keys$'; then
    echo "Error: please cd to outside of 'keys' directory."
    exit 1
fi

export BASEDIR=`mktemp -d "/tmp/zone_sign-XXX"`
../../../../tools/zone_sign.sh example. ../../../../data/example.zone nsec
mv ../../../../data/example.zone.signed ./example.zone

rm -rf keys
mkdir keys
pushd keys
for key in "$BASEDIR"/*.private; do
    "$KEYMGR" -d . example. import-bind "$key"
done
popd
