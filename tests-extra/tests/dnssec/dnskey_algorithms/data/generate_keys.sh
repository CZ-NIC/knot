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

# KSK+ZSK, simple
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa

# KSK+ZSK, two algorithms
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa
keygen -a ECDSAP256SHA256 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa
keygen -a ECDSAP256SHA256 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa

# KSK+ZSK: RSA enabled, ECDSA in future
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_now_ecdsa_future
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_now_ecdsa_future
keygen -a ECDSAP256SHA256 -P $TIME_FUTURE -A $TIME_FUTURE -f KSK rsa_now_ecdsa_future
keygen -a ECDSAP256SHA256 -P $TIME_FUTURE -A $TIME_FUTURE rsa_now_ecdsa_future

# KSK+ZSK, algorithm rollover (signatures pre-published)
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_ecdsa_roll
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_ecdsa_roll
keygen -a ECDSAP256SHA256 -P $TIME_FUTURE -A $TIME_PAST -f KSK rsa_ecdsa_roll
keygen -a ECDSAP256SHA256 -P $TIME_FUTURE -A $TIME_PAST rsa_ecdsa_roll

# STSS: KSK only
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK stss_ksk

# STSS: ZSK only
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST stss_zsk

# STSS: two KSKs
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST -f KSK stss_two_ksk
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST -f KSK stss_two_ksk

# STSS: different algorithms
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK stss_rsa256_rsa512
keygen -a RSASHA512 -b 2048 -P $TIME_PAST -A $TIME_PAST stss_rsa256_rsa512

# KSK+ZSK for RSA, STSS for ECDSA
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_split_ecdsa_stss
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_split_ecdsa_stss
keygen -a ECDSAP256SHA256 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_split_ecdsa_stss

#
# invalid scenarios
#

# no key for now
keygen -a RSASHA256 -b 2048 -P $TIME_FUTURE -A $TIME_FUTURE -f KSK rsa_future_all
keygen -a RSASHA256 -b 1024 -P $TIME_FUTURE -A $TIME_FUTURE rsa_future_all

# key active, not published
keygen -a RSASHA512 -b 2048 -P $TIME_FUTURE -A $TIME_PAST -f KSK rsa_future_publish
keygen -a RSASHA256 -b 1024 -P $TIME_FUTURE -A $TIME_PAST rsa_future_publish

# key published, not active
keygen -a RSASHA512 -b 2048 -P $TIME_PAST -A $TIME_FUTURE -f KSK rsa_future_active
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_FUTURE rsa_future_active

# no signatures for KSK
keygen -a RSASHA256 -b 2048 -P $TIME_PAST -A $TIME_PAST -f KSK rsa_inactive_zsk
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_FUTURE rsa_inactive_zsk

# no signatures for ZSK
keygen -a RSASHA256 -b 2048 -P $TIME_FUTURE -A $TIME_FUTURE -f KSK rsa_no_zsk
keygen -a RSASHA256 -b 1024 -P $TIME_PAST -A $TIME_PAST rsa_no_zsk

tar czf "$dir/keys.tgz" K*.{key,private}
popd
rm -rf "$keydir"
