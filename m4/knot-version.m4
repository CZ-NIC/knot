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

m4_define([knot_GIT_REMOTE], m4_esyscmd_s(git rev-parse --abbrev-ref --symbolic-full-name @{u} | cut -d"/" -f1 2>/dev/null))dnl
m4_define([knot_GIT_URL],    m4_esyscmd_s(git config --get remote.knot_GIT_REMOTE.url 2>/dev/null))dnl
m4_define([knot_GIT_GITLAB], m4_esyscmd_s(echo knot_GIT_URL | grep "gitlab.labs.nic.cz/knot/" - 2>/dev/null))dnl
m4_define([knot_GIT_GITHUB], m4_esyscmd_s(echo knot_GIT_URL | grep "github.com/CZ-NIC/knot/" - 2>/dev/null))dnl
m4_define([knot_GIT_HASH],   m4_esyscmd_s(git rev-parse --short HEAD 2>/dev/null))dnl
m4_define([knot_GIT_TAG],    m4_esyscmd_s(git describe --exact-match 2>/dev/null))dnl
m4_define([knot_TIMESTAMP],  m4_esyscmd_s(date -u +'%s' 2>/dev/null))dnl
m4_define([knot_GIT_OK],     m4_ifnblank(knot_GIT_HASH, m4_ifnblank(knot_GIT_GITLAB, [ok], m4_ifnblank(knot_GIT_GITHUB, [ok], [])), []))dnl
m4_define([knot_GIT_INFO],   m4_ifblank(knot_GIT_TAG, m4_ifnblank(knot_GIT_OK, .knot_TIMESTAMP.knot_GIT_HASH, []), []))dnl

m4_define([knot_PKG_VERSION], [knot_VERSION_MAJOR.knot_VERSION_MINOR.knot_PATCH]knot_GIT_INFO)dnl
