#!/bin/sh
#
# Run this script every 40 years to refresh the keys. :-)
#

set -xe

KEYMGR=${1:-keymgr}
keydir=$(pwd)/keys

rm -rf "${keydir}"
mkdir -p "${keydir}"

TIME_PAST="-40y"
TIME_FUTURE="+40y"

pushd "$keydir"

#
# valid scenarios
#

# KSK+ZSK, simple
"$KEYMGR" -d . rsa. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=False

# KSK+ZSK, two algorithms
"$KEYMGR" -d . rsa_ecdsa. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_ecdsa. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=False
"$KEYMGR" -d . rsa_ecdsa. generate algorithm=13 size=256 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_ecdsa. generate algorithm=13 size=256 publish="$TIME_PAST" active="$TIME_PAST" ksk=False

# KSK+ZSK: RSA enabled, ECDSA in future
"$KEYMGR" -d . rsa_now_ecdsa_future. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_now_ecdsa_future. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=False
"$KEYMGR" -d . rsa_now_ecdsa_future. generate algorithm=13 size=256 publish="$TIME_FUTURE" active="$TIME_FUTURE" ksk=True
"$KEYMGR" -d . rsa_now_ecdsa_future. generate algorithm=13 size=256 publish="$TIME_FUTURE" active="$TIME_FUTURE" ksk=False

# KSK+ZSK, algorithm rollover (signatures pre-published)
"$KEYMGR" -d . rsa_ecdsa_roll. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_ecdsa_roll. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=False
"$KEYMGR" -d . rsa_ecdsa_roll. generate algorithm=13 size=256 publish="$TIME_FUTURE" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_ecdsa_roll. generate algorithm=13 size=256 publish="$TIME_FUTURE" active="$TIME_PAST" ksk=False

# STSS: KSK only
"$KEYMGR" -d . stss_ksk. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True

# STSS: ZSK only
"$KEYMGR" -d . stss_zsk. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=False

# STSS: two KSKs
"$KEYMGR" -d . stss_two_ksk. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . stss_two_ksk. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=True

# STSS: different algorithms
"$KEYMGR" -d . stss_rsa256_rsa512. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . stss_rsa256_rsa512. generate algorithm=10 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=False

# KSK+ZSK for RSA, STSS for ECDSA
"$KEYMGR" -d . rsa_split_ecdsa_stss. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_split_ecdsa_stss. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=False
"$KEYMGR" -d . rsa_split_ecdsa_stss. generate algorithm=13 size=256 publish="$TIME_PAST" active="$TIME_PAST" ksk=True

#
# invalid scenarios
#

# no key for now
"$KEYMGR" -d . rsa_future_all. generate algorithm=8 size=2048 publish="$TIME_FUTURE" active="$TIME_FUTURE" ksk=True
"$KEYMGR" -d . rsa_future_all. generate algorithm=8 size=1024 publish="$TIME_FUTURE" active="$TIME_FUTURE" ksk=False

# key active, not published
"$KEYMGR" -d . rsa_future_publish. generate algorithm=8 size=2048 publish="$TIME_FUTURE" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_future_publish. generate algorithm=8 size=1024 publish="$TIME_FUTURE" active="$TIME_PAST" ksk=False

# key published, not active
"$KEYMGR" -d . rsa_future_active. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_FUTURE" ksk=True
"$KEYMGR" -d . rsa_future_active. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_FUTURE" ksk=False

# no signatures for KSK
"$KEYMGR" -d . rsa_inactive_zsk. generate algorithm=8 size=2048 publish="$TIME_PAST" active="$TIME_PAST" ksk=True
"$KEYMGR" -d . rsa_inactive_zsk. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_FUTURE" ksk=False

# no signatures for ZSK
"$KEYMGR" -d . rsa_no_zsk. generate algorithm=8 size=2048 publish="$TIME_FUTURE" active="$TIME_FUTURE" ksk=True
"$KEYMGR" -d . rsa_no_zsk. generate algorithm=8 size=1024 publish="$TIME_PAST" active="$TIME_PAST" ksk=False

popd
