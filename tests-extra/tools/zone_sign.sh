#!/bin/bash
export SIGNKEY=""
export KSK=""
export STYPE="-3"
export ENDTIME="20500101000000"
_keygen() {
        keygenlog=${BASEDIR}/keygen.log
        echo -n > $keygenlog
        key=$(dnssec-keygen -r /dev/urandom $STYPE -n ZONE -K $BASEDIR $ZONE 2>>$keygenlog)
        export SIGNKEY=$BASEDIR/${key}
        key=$(dnssec-keygen $STYPE -f KSK -r /dev/urandom -n ZONE -K $BASEDIR $ZONE 2>>$keygenlog)
        export KSK=$BASEDIR/${key}
        #echo "\$include $SIGNKEY.key ; ZSK" >> $ZFILE
        #echo "\$include $KSK.key ; KSK" >> $ZFILE
}

_sign_zone() {
        flags=""
        if [ "$STYPE" == "-3" ]; then
                flags="$STYPE deadbeef"
        fi
        dnssec-signzone $flags -O full -d $BASEDIR -K $BASEDIR -k ${KSK} -e $ENDTIME \
			-S -o $ZONE $1 $SIGNKEY.key &>>$LOG
}

if [ "$(basename $0)" == "zone_sign.sh" ] && [ $# -ge 2 ]; then
        if [ -z $BASEDIR ]; then
                export BASEDIR=$(pwd)
        fi
        export LOG=.log
        export ZONE=$1
        export ZFILE=$2
        if [ "$3" == "nsec" ]; then
                STYPE=""
        fi
        if [ -n "$4" ]; then
                ENDTIME=$4
        fi
        if [ -f .skey ] && [ -f .ksk ]; then
                export SIGNKEY=$(cat .skey)
                export KSK=$(cat .ksk)
        else
                _keygen
                echo $SIGNKEY > .skey
                echo $KSK > .ksk
                mv .skey $BASEDIR &>>$LOG
                mv .ksk $BASEDIR &>>$LOG
        fi
        _sign_zone $ZFILE
        cat $LOG
        rm $LOG
fi
