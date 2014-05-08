#!/bin/sh

SIGN="../../../../../tools/zone_sign.sh"
TPL="./example.com.zone.template"
ZFIN="../example.com.zone.in"
ZF="../example.com.zone"

# 0.
SERIAL=1
sed "s/#SERIAL#/${SERIAL}/" $TPL > $ZFIN
mv $ZFIN $ZF

# 1.
SERIAL=2
sed "s/#SERIAL#/${SERIAL}/" $TPL > $ZFIN
export BASEDIR=`mktemp -d "/tmp/zone_sign-XXX"`
$SIGN example.com. $ZFIN
mv $ZFIN.signed $ZF.1

# 2.
SERIAL=3
sed "s/#SERIAL#/${SERIAL}/" $TPL > $ZFIN
export BASEDIR=`mktemp -d "/tmp/zone_sign-XXX"`
$SIGN example.com. $ZFIN nsec
mv $ZFIN.signed $ZF.2

# 3.
SERIAL=4
sed "s/#SERIAL#/${SERIAL}/" $TPL > $ZFIN
mv $ZFIN $ZF.3
