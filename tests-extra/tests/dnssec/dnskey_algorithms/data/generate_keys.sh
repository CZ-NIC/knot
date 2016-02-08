#!/bin/sh
#
# Run this script every 40 years to refresh the keys. :-)
#

set -xe

KEYMGR=${1:-keymgr}
dir=$(pwd)
keydir=$(mktemp -d)

TIME_PAST="-40y"
TIME_FUTURE="+40y"

pushd "$keydir"

"$KEYMGR" init
"$KEYMGR" policy set default manual true

#
# valid scenarios
#

# KSK+ZSK, simple
"$KEYMGR" zone add rsa
"$KEYMGR" zone key generate rsa algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST"

# KSK+ZSK, two algorithms
"$KEYMGR" zone add rsa_ecdsa
"$KEYMGR" zone key generate rsa_ecdsa algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_ecdsa algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST"
"$KEYMGR" zone key generate rsa_ecdsa algorithm 13 size 256 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_ecdsa algorithm 13 size 256 publish "$TIME_PAST" active "$TIME_PAST"

# KSK+ZSK: RSA enabled, ECDSA in future
"$KEYMGR" zone add rsa_now_ecdsa_future
"$KEYMGR" zone key generate rsa_now_ecdsa_future algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_now_ecdsa_future algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST"
"$KEYMGR" zone key generate rsa_now_ecdsa_future algorithm 13 size 256 publish "$TIME_FUTURE" active "$TIME_FUTURE" ksk
"$KEYMGR" zone key generate rsa_now_ecdsa_future algorithm 13 size 256 publish "$TIME_FUTURE" active "$TIME_FUTURE"

# KSK+ZSK, algorithm rollover (signatures pre-published)
"$KEYMGR" zone add rsa_ecdsa_roll
"$KEYMGR" zone key generate rsa_ecdsa_roll algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_ecdsa_roll algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST"
"$KEYMGR" zone key generate rsa_ecdsa_roll algorithm 13 size 256 publish "$TIME_FUTURE" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_ecdsa_roll algorithm 13 size 256 publish "$TIME_FUTURE" active "$TIME_PAST"

# STSS: KSK only
"$KEYMGR" zone add stss_ksk
keymgr zone key generate stss_ksk algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk

# STSS: ZSK only
"$KEYMGR" zone add stss_zsk
"$KEYMGR" zone key generate stss_zsk algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST"

# STSS: two KSKs
"$KEYMGR" zone add stss_two_ksk
"$KEYMGR" zone key generate stss_two_ksk algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate stss_two_ksk algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST" ksk

# STSS: different algorithms
"$KEYMGR" zone add stss_rsa256_rsa512
"$KEYMGR" zone key generate stss_rsa256_rsa512 algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate stss_rsa256_rsa512 algorithm 10 size 2048 publish "$TIME_PAST" active "$TIME_PAST"

# KSK+ZSK for RSA, STSS for ECDSA
"$KEYMGR" zone add rsa_split_ecdsa_stss
"$KEYMGR" zone key generate rsa_split_ecdsa_stss algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_split_ecdsa_stss algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST"
"$KEYMGR" zone key generate rsa_split_ecdsa_stss algorithm 13 size 256 publish "$TIME_PAST" active "$TIME_PAST" ksk

#
# invalid scenarios
#

# no key for now
"$KEYMGR" zone add rsa_future_all
"$KEYMGR" zone key generate rsa_future_all algorithm 8 size 2048 publish "$TIME_FUTURE" active "$TIME_FUTURE" ksk
"$KEYMGR" zone key generate rsa_future_all algorithm 8 size 1024 publish "$TIME_FUTURE" active "$TIME_FUTURE"

# key active, not published
"$KEYMGR" zone add rsa_future_publish
"$KEYMGR" zone key generate rsa_future_publish algorithm 8 size 2048 publish "$TIME_FUTURE" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_future_publish algorithm 8 size 1024 publish "$TIME_FUTURE" active "$TIME_PAST"

# key published, not active
"$KEYMGR" zone add rsa_future_active
"$KEYMGR" zone key generate rsa_future_active algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_FUTURE" ksk
"$KEYMGR" zone key generate rsa_future_active algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_FUTURE"

# no signatures for KSK
"$KEYMGR" zone add rsa_inactive_zsk
"$KEYMGR" zone key generate rsa_inactive_zsk algorithm 8 size 2048 publish "$TIME_PAST" active "$TIME_PAST" ksk
"$KEYMGR" zone key generate rsa_inactive_zsk algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_FUTURE"

# no signatures for ZSK
"$KEYMGR" zone add rsa_no_zsk
"$KEYMGR" zone key generate rsa_no_zsk algorithm 8 size 2048 publish "$TIME_FUTURE" active "$TIME_FUTURE" ksk
"$KEYMGR" zone key generate rsa_no_zsk algorithm 8 size 1024 publish "$TIME_PAST" active "$TIME_PAST"

tar czf "$dir/keys.tgz" keys {policy,keystore,zone}_*.json
popd
rm -rf "$keydir"
