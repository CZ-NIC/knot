#!/bin/bash

for zone in $(cat zones); do
    for key in K$zone*.private; do
	pem=${key/.private}.pem
	softhsm-keyconv --topkcs8 --in $key --out $pem;
	id=$(openssl rsa -in $pem -pubout -outform DER | sha1sum | cut -f 1 -d " ")
	rm -f keys/$id.pem
	cp $pem keys/$id.pem;
	pub=${key/.private}.key

	tag=$(echo $key | sed -e 's/^.*+//;s/\.private$//')
	algo=8 #$(echo $key | sed -e 's/^[^+]*+//;s/+[^+]*$//')
	public=$(cat $pub | grep -Ev "^;" | cut -f 7- -d ' ' | sed -e 's/ //g')

	if grep -q 257 $pub; then
	    KSK=true
	else
	    KSK=false
	fi
	if $KSK; then
	    KSKID=$id
	    KSKTAG=$tag
	    KSKALGO=$algo
	    KSKKEY=$public
	else
	    ZSKID=$id
	    ZSKTAG=$tag
	    ZSKALGO=$algo
	    ZSKKEY=$public
	fi
    done;
    < template.json sed \
	-e "s{|KSKID|{${KSKID}{;" \
	-e "s{|KSKTAG|{${KSKTAG}{;" \
	-e "s{|KSKALGO|{${KSKALGO}{;" \
	-e "s{|KSKKEY|{${KSKKEY}{;" \
	-e "s{|ZSKID|{${ZSKID}{;" \
	-e "s{|ZSKTAG|{${ZSKTAG}{;" \
	-e "s{|ZSKALGO|{${ZSKALGO}{;" \
	-e "s{|ZSKKEY|{${ZSKKEY}{;" \
	> zone_${zone}.json
done
