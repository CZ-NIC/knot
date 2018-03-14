################################################################################
# Knot DNS versions are as follows
#
# <MAJOR>.<MINOR>.dev[.<TIMESTAMP>.<HASH>]        Build from the master branch
# <MAJOR>.<MINOR>.<PATCH>[.<TIMESTAMP>.<HASH>]    Build from a feature branch
#
# If the repository is not available or if HEAD is tagged,
# the optional part is missing!
#
# Example: 2.7.dev.1521027664.5e69ccc
################################################################################

m4_define([knot_PATCH],     m4_ifblank(knot_VERSION_PATCH, [dev], knot_VERSION_PATCH))dnl
m4_define([knot_GIT_HASH],  m4_esyscmd_s(git rev-parse --short HEAD 2>/dev/null))dnl
m4_define([knot_GIT_TAG],   m4_esyscmd_s(git describe --exact-match 2>/dev/null))dnl
m4_define([knot_TIMESTAMP], m4_esyscmd_s(date -u +'%s' 2>/dev/null))dnl
m4_define([knot_GIT_INFO],  m4_ifblank(knot_GIT_TAG, m4_ifnblank(knot_GIT_HASH, .knot_TIMESTAMP.knot_GIT_HASH, []), []))dnl

m4_define([knot_PKG_VERSION], [knot_VERSION_MAJOR.knot_VERSION_MINOR.knot_PATCH]knot_GIT_INFO)dnl
