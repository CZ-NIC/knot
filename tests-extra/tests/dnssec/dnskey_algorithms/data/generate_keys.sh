#!/bin/sh
#
# Run this script every 50 years to refresh the keys. :-)
#

set -xe

TIME_PAST="-50y"
TIME_FUTURE="+50y"

keygen()
{
	dnssec-keygen -r/dev/urandom $@
}

dir=$(pwd)
keydir=$(mktemp -d)

pushd "$keydir"

#
# valid scenarios
#

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ok
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_ok

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa_ok
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa_ok
keygen -a ECDSAP256SHA256 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa_ok
keygen -a ECDSAP256SHA256 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa_ok

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa_roll_ok
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa_roll_ok
keygen -a ECDSAP256SHA256 -P $TIME_FUTURE -A $TIME_PAST rsa_ecdsa_roll_ok

#
# invalid scenarios
#

keygen -a RSASHA256 -b 2048 -P $TIME_FUTURE -A $TIME_FUTURE -f KSK rsa_future_all
keygen -a RSASHA256 -b 1024 -P $TIME_FUTURE -A $TIME_FUTURE rsa_future_all

keygen -a RSASHA512 -b 2048 -P $TIME_FUTURE -A $TIME_PAST -f KSK rsa_future_publish
keygen -a RSASHA256 -b 1024 -P $TIME_FUTURE -A $TIME_PAST rsa_future_publish

keygen -a RSASHA512 -b 2048 -P $TIME_PAST -A $TIME_FUTURE -f KSK rsa_future_active
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_FUTURE rsa_future_active

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_inactive_zsk
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_FUTURE rsa_inactive_zsk

keygen -a RSASHA256 -b 2048 -P $TIME_FUTURE -A $TIME_FUTURE -f KSK rsa_no_zsk
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_no_zsk

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_twice_ksk
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_twice_ksk

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa_ksk_only
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa_ksk_only
keygen -a ECDSAP256SHA256 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa_ksk_only

keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa256_rsa512
keygen -a RSASHA512 -b 2048 -P $TIME_PAST -A $TIME_PAST rsa256_rsa512

tar czf "$dir/keys.tgz" K*.{key,private}
popd
rm -rf "$keydir"
