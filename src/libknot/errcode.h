/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \file
 *
 * \brief Knot error codes.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <errno.h>

/*! \brief Error codes used in the library. */
enum knot_error {
	KNOT_EOK = 0,

	/* Directly mapped error codes. */
	KNOT_ENOMEM        = -ENOMEM,
	KNOT_EINVAL        = -EINVAL,
	KNOT_ENOTSUP       = -ENOTSUP,
	KNOT_EBUSY         = -EBUSY,
	KNOT_EAGAIN        = -EAGAIN,
	KNOT_ENOBUFS       = -ENOBUFS,
	KNOT_EMFILE        = -EMFILE,
	KNOT_ENFILE        = -ENFILE,
	KNOT_EACCES        = -EACCES,
	KNOT_EISCONN       = -EISCONN,
	KNOT_ECONNREFUSED  = -ECONNREFUSED,
	KNOT_EALREADY      = -EALREADY,
	KNOT_ECONNRESET    = -ECONNRESET,
	KNOT_ECONNABORTED  = -ECONNABORTED,
	KNOT_ENETRESET     = -ENETRESET,
	KNOT_EHOSTUNREACH  = -EHOSTUNREACH,
	KNOT_ENETUNREACH   = -ENETUNREACH,
	KNOT_EHOSTDOWN     = -EHOSTDOWN,
	KNOT_ENETDOWN      = -ENETDOWN,
	KNOT_EADDRINUSE    = -EADDRINUSE,
	KNOT_ENOENT        = -ENOENT,
	KNOT_EEXIST        = -EEXIST,
	KNOT_ERANGE        = -ERANGE,
	KNOT_EADDRNOTAVAIL = -EADDRNOTAVAIL,
	KNOT_ENOTDIR       = -ENOTDIR,

	KNOT_ERRNO_ERROR   = -500,

	KNOT_ERROR_MIN = -1000,

	/* General errors. */
	KNOT_ERROR = KNOT_ERROR_MIN,
	KNOT_EPARSEFAIL,
	KNOT_ESEMCHECK,
	KNOT_EUPTODATE,
	KNOT_EFEWDATA,
	KNOT_ESPACE,
	KNOT_EMALF,
	KNOT_ENSEC3PAR,
	KNOT_ENSEC3CHAIN,
	KNOT_EOUTOFZONE,
	KNOT_EZONEINVAL,
	KNOT_ENOZONE,
	KNOT_ENONODE,
	KNOT_ENORECORD,
	KNOT_EISRECORD,
	KNOT_ENOMASTER,
	KNOT_EPREREQ,
	KNOT_ETTL,
	KNOT_ENOXFR,
	KNOT_EDENIED,
	KNOT_ECONN,
	KNOT_ETIMEOUT,
	KNOT_ENODIFF,
	KNOT_ENOTSIG,
	KNOT_ELIMIT,
	KNOT_EZONESIZE,
	KNOT_EOF,
	KNOT_ESYSTEM,
	KNOT_EFILE,
	KNOT_ESOAINVAL,
	KNOT_ETRAIL,
	KNOT_EPROCESSING,
	KNOT_EPROGRESS,
	KNOT_ELOOP,
	KNOT_EPROGRAM,
	KNOT_EFD,
	KNOT_ENOPARAM,
	KNOT_EXPARAM,
	KNOT_EEMPTYZONE,
	KNOT_ENODB,
	KNOT_EUNREACH,

	KNOT_GENERAL_ERROR = -900,

	/* Control states. */
	KNOT_CTL_ESTOP,
	KNOT_CTL_EZONE,

	/* Network errors. */
	KNOT_NET_EADDR,
	KNOT_NET_ESOCKET,
	KNOT_NET_ECONNECT,
	KNOT_NET_ESEND,
	KNOT_NET_ERECV,
	KNOT_NET_ETIMEOUT,

	/* Encoding errors. */
	KNOT_BASE64_ESIZE,
	KNOT_BASE64_ECHAR,
	KNOT_BASE32HEX_ESIZE,
	KNOT_BASE32HEX_ECHAR,

	/* TSIG errors. */
	KNOT_TSIG_EBADSIG,
	KNOT_TSIG_EBADKEY,
	KNOT_TSIG_EBADTIME,
	KNOT_TSIG_EBADTRUNC,

	/* DNSSEC errors. */
	KNOT_DNSSEC_EMISSINGKEYTYPE,
	KNOT_DNSSEC_ENOKEY,
	KNOT_DNSSEC_ENOSIG,
	KNOT_DNSSEC_ENSEC_BITMAP,
	KNOT_DNSSEC_ENSEC_CHAIN,
	KNOT_DNSSEC_ENSEC3_OPTOUT,

	/* Yparser errors. */
	KNOT_YP_ECHAR_TAB,
	KNOT_YP_EINVAL_ITEM,
	KNOT_YP_EINVAL_ID,
	KNOT_YP_EINVAL_DATA,
	KNOT_YP_EINVAL_INDENT,
	KNOT_YP_ENOTSUP_DATA,
	KNOT_YP_ENOTSUP_ID,
	KNOT_YP_ENODATA,
	KNOT_YP_ENOID,

	/* Configuration errors. */
	KNOT_CONF_ENOTINIT,
	KNOT_CONF_EVERSION,
	KNOT_CONF_EREDEFINE,

	/* Transaction errors. */
	KNOT_TXN_EEXISTS,
	KNOT_TXN_ENOTEXISTS,

	/* DNSSEC errors. */
	KNOT_INVALID_PUBLIC_KEY,
	KNOT_INVALID_PRIVATE_KEY,
	KNOT_INVALID_KEY_ALGORITHM,
	KNOT_INVALID_KEY_SIZE,
	KNOT_INVALID_KEY_ID,
	KNOT_INVALID_KEY_NAME,
	KNOT_NO_PUBLIC_KEY,
	KNOT_NO_PRIVATE_KEY,
	KNOT_NO_READY_KEY,

	KNOT_ERROR_MAX = -501
};

/*!
 * \brief Map POSIX errno code to Knot error code.
 *
 * \param code       Errno code to transform (set -1 to use the current errno).
 * \param dflt_error Default return value, if code is unknown.
 *
 * \return Mapped errno or the value of dflt_error if unknown.
 */
inline static int knot_map_errno_code_def(int code, int dflt_error)
{
	if (code < 0) {
		code = errno;
	}

	typedef struct {
		int errno_code;
		int libknot_code;
	} err_table_t;

	#define ERR_ITEM(name) { name, KNOT_##name }
	static const err_table_t errno_to_errcode[] = {
		ERR_ITEM(ENOMEM),
		ERR_ITEM(EINVAL),
		ERR_ITEM(ENOTSUP),
		ERR_ITEM(EBUSY),
		ERR_ITEM(EAGAIN),
		ERR_ITEM(ENOBUFS),
		ERR_ITEM(EMFILE),
		ERR_ITEM(ENFILE),
		ERR_ITEM(EACCES),
		ERR_ITEM(EISCONN),
		ERR_ITEM(ECONNREFUSED),
		ERR_ITEM(EALREADY),
		ERR_ITEM(ECONNRESET),
		ERR_ITEM(ECONNABORTED),
		ERR_ITEM(ENETRESET),
		ERR_ITEM(EHOSTUNREACH),
		ERR_ITEM(ENETUNREACH),
		ERR_ITEM(EHOSTDOWN),
		ERR_ITEM(ENETDOWN),
		ERR_ITEM(EADDRINUSE),
		ERR_ITEM(ENOENT),
		ERR_ITEM(EEXIST),
		ERR_ITEM(ERANGE),
		ERR_ITEM(EADDRNOTAVAIL),

		/* Terminator - the value isn't used. */
		{ 0, KNOT_ERRNO_ERROR }
	};
	#undef ERR_ITEM

	const err_table_t *err = errno_to_errcode;

	while (err->errno_code != 0 && err->errno_code != code) {
		err++;
	}

	return err->errno_code != 0 ? err->libknot_code : dflt_error;
}

/*!
 * \brief Map POSIX errno code to Knot error code.
 *
 * \param code Errno code to transform (set -1 to use the current errno).
 *
 * \return Mapped errno or KNOT_ERRNO_ERROR if unknown.
 */
inline static int knot_map_errno_code(int code)
{
	return knot_map_errno_code_def(code, KNOT_ERRNO_ERROR);
}

/*!
 * \brief Get a POSIX errno mapped to Knot error code.
 *
 * \param dflt_error Default return value, if code is unknown.
 *
 * \return Mapped errno.
 */
inline static int knot_map_errno_def(int dflt_error)
{
	return knot_map_errno_code_def(-1, dflt_error);
}

/*!
 * \brief Get a POSIX errno mapped to Knot error code.
 *
 * \return Mapped errno or KNOT_ERRNO_ERROR if unknown.
 */
inline static int knot_map_errno(void)
{
	return knot_map_errno_code_def(-1, KNOT_ERRNO_ERROR);
}

/*! @} */
