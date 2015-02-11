#!/bin/sh

set -e

KEYMGR=${KEYMGR:-keymgr}

export BASEDIR=`mktemp -d "/tmp/zone_sign-XXX"`
../../../../tools/zone_sign.sh example. ../../../../data/example.zone nsec
mv ../../../../data/example.zone.signed ./example.zone

rm -rf keys
mkdir keys
pushd keys
"$KEYMGR" init
"$KEYMGR" zone add example
for key in "$BASEDIR"/*.private; do
    "$KEYMGR" zone key import example "$key"
done
popd
