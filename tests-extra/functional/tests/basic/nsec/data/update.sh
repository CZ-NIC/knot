#!/bin/sh

export BASEDIR=`mktemp -d "/tmp/zone_sign-XXX"`
../../../../tools/zone_sign.sh example. ../../../../data/example.zone nsec
mv ../../../../data/example.zone.signed ./example.zone.nsec
