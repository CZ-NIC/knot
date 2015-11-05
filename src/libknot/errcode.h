/*!
* \file errcode.h
*
* \author Lubos Slovak <lubos.slovak@nic.cz>
* \author Marek Vavrusa <marek.vavrusa@nic.cz>
*
* \brief Error codes and function for getting error message.
*
* \addtogroup common_lib
* @{
*/
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <errno.h>

/* errno -> Knot error mapping.
 * \note offset is required, otherwise it would interfere with TSIG errors.
 */
#define KNOT_ERROR_BASE 100
#define knot_errno_to_error(x) (-(KNOT_ERROR_BASE + (x)))

/*! \brief Error codes used in the library. */
enum knot_error {
	KNOT_EOK = 0,

	/* TSIG errors. */
	KNOT_TSIG_EBADSIG = -16,
	KNOT_TSIG_EBADKEY = -17,
	KNOT_TSIG_EBADTIME = -18,

	/* Directly mapped error codes. */
	KNOT_ENOMEM = knot_errno_to_error(ENOMEM),
	KNOT_EINVAL = knot_errno_to_error(EINVAL),
	KNOT_ENOTSUP = knot_errno_to_error(ENOTSUP),
	KNOT_EBUSY = knot_errno_to_error(EBUSY),
	KNOT_EAGAIN = knot_errno_to_error(EAGAIN),
	KNOT_EACCES = knot_errno_to_error(EACCES),
	KNOT_ECONNREFUSED = knot_errno_to_error(ECONNREFUSED),
	KNOT_EISCONN = knot_errno_to_error(EISCONN),
	KNOT_EADDRINUSE = knot_errno_to_error(EADDRINUSE),
	KNOT_ENOENT = knot_errno_to_error(ENOENT),
	KNOT_EEXIST = knot_errno_to_error(EEXIST),
	KNOT_ERANGE = knot_errno_to_error(ERANGE),

	/* General errors. */
	KNOT_ERROR = -10000,
	KNOT_ENOTRUNNING,
	KNOT_EPARSEFAIL,
	KNOT_ESEMCHECK,
	KNOT_EEXPIRED,
	KNOT_EUPTODATE,
	KNOT_EFEWDATA,
	KNOT_ESPACE,
	KNOT_EMALF,
	KNOT_ECRYPTO,
	KNOT_ENSEC3PAR,
	KNOT_ENSEC3CHAIN,
    KNOT_ENSEC5CHAIN,
	KNOT_EOUTOFZONE,
	KNOT_EHASH,
	KNOT_EZONEINVAL,
	KNOT_EZONENOENT,
	KNOT_ENOZONE,
	KNOT_ENONODE,
	KNOT_ENOMASTER,
	KNOT_EDNAMEPTR,
	KNOT_EPAYLOAD,
	KNOT_ECRC,
	KNOT_EPREREQ,
	KNOT_ETTL,
	KNOT_ENOXFR,
	KNOT_ENOIXFR,
	KNOT_EXFRREFUSED,
	KNOT_EDENIED,
	KNOT_ECONN,
	KNOT_ETIMEOUT,
	KNOT_EIXFRSPACE,
	KNOT_ECNAME,
	KNOT_ENODIFF,
	KNOT_EDSDIGESTLEN,
	KNOT_ENOTSIG,
	KNOT_ELIMIT,
	KNOT_EWRITABLE,
	KNOT_EOF,

	/* Control states. */
	KNOT_CTL_STOP,
	KNOT_CTL_ACCEPTED,

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

	/* Key parsing errors. */
	KNOT_KEY_EPUBLIC_KEY_OPEN,
	KNOT_KEY_EPRIVATE_KEY_OPEN,
	KNOT_KEY_EPUBLIC_KEY_INVALID,

	/* Key signing errors. */
	KNOT_DNSSEC_ENOTSUP,
	KNOT_DNSSEC_EINVALID_KEY,
	KNOT_DNSSEC_EASSIGN_KEY,
	KNOT_DNSSEC_ECREATE_DIGEST_CONTEXT,
	KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE,
	KNOT_DNSSEC_EDECODE_RAW_SIGNATURE,
	KNOT_DNSSEC_EINVALID_SIGNATURE,
	KNOT_DNSSEC_ESIGN,
	KNOT_DNSSEC_ENOKEY,
	KNOT_DNSSEC_ENOKEYDIR,
	KNOT_DNSSEC_EMISSINGKEYTYPE,
    
    /* Key signing errors for NSEC5. */
    KNOT_NSEC5_ENOTSUP,
    KNOT_NSEC5_EINVALID_KEY,
    KNOT_NSEC5_EASSIGN_KEY,
    KNOT_NSEC5_ECREATE_DIGEST_CONTEXT,
    KNOT_NSEC5_EUNEXPECTED_SIGNATURE_SIZE,
    KNOT_NSEC5_EDECODE_RAW_SIGNATURE,
    KNOT_NSEC5_EINVALID_SIGNATURE,
    KNOT_NSEC5_ESIGN,
    KNOT_NSEC5_ENOKEY,
    KNOT_NSEC5_ENOKEYDIR,
    KNOT_NSEC5_EMISSINGKEYTYPE,


	/* NSEC3 errors. */
	KNOT_NSEC3_ECOMPUTE_HASH,
    
    /* dipapado: NSEC5 errors. */
    KNOT_NSEC5_ECOMPUTE_HASH,
    
    KNOT_ZONE_KEY_ADD_ERROR,

	/* Database backend. */
	KNOT_DATABASE_ERROR
};

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
const char *knot_strerror(int code);

/*!
 * \brief Get a POSIX errno mapped to Knot error code.
 *
 * \internal
 *
 * \param fallback  Falback error code.
 * \param arg0...   Error codes allowed for lookup, list must be terminated by 0.
 *
 * \return Mapped errno or fallback error code.
 */
int knot_map_errno_internal(int fallback, int arg0, ...);

/*!
 * \brief Map POSIX errno to Knot error code.
 *
 * KNOT_ERROR is used as a fallback error, the list is terminated implicitly.
 */
#define knot_map_errno(errors...) knot_map_errno_internal(KNOT_ERROR, errors, 0)

/*! @} */
