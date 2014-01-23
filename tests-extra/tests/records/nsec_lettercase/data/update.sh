#!/bin/sh

export BASEDIR=`mktemp -d "/tmp/zone_sign-XXX"`
../../../../tools/zone_sign.sh rdatacase. ./rdatacase.zone nsec
