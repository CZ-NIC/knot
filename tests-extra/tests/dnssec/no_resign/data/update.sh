#!/bin/sh

set -e

KKEYMGR=${KKEYMGR:-kkeymgr}

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
