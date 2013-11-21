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

#ifndef _KNOTD_COMMON_ERRCODE_H_
#define _KNOTD_COMMON_ERRCODE_H_

#include "common/errors.h"

/* errno -> Knot error mapping.
 * \note offset is required, otherwise it would interfere with TSIG errors.
 */
#define ERRBASE 100
#define err2code(x) (-(ERRBASE + (x)))

/*! \brief Error codes used in the library. */
enum knot_error {
	KNOT_EOK = 0,             /*!< OK */

	/* TSIG errors. */
	KNOT_TSIG_EBADSIG = -16,  /*!< Failed to verify TSIG MAC. */
	KNOT_TSIG_EBADKEY = -17,  /*!< TSIG key not recognized or invalid. */
	KNOT_TSIG_EBADTIME = -18, /*!< TSIG signing time out of range. */

	/* Directly mapped error codes. */
	KNOT_ENOMEM = err2code(ENOMEM),             /*!< Out of memory. */
	KNOT_EINVAL = err2code(EINVAL),             /*!< Invalid parameter passed. */
	KNOT_ENOTSUP = err2code(ENOTSUP),           /*!< Parameter not supported. */
	KNOT_EBUSY = err2code(EBUSY),               /*!< Requested resource is busy. */
	KNOT_EAGAIN = err2code(EAGAIN),             /*!< OS lacked necessary resources. */
	KNOT_EACCES = err2code(EACCES),             /*!< Permission is denied. */
	KNOT_ECONNREFUSED = err2code(ECONNREFUSED), /*!< Connection is refused. */
	KNOT_EISCONN = err2code(EISCONN),           /*!< Already connected. */
	KNOT_EADDRINUSE = err2code(EADDRINUSE),     /*!< Address already in use. */
	KNOT_ENOENT = err2code(ENOENT),             /*!< Resource not found. */
	KNOT_ERANGE = err2code(ERANGE),             /*!< Value is out of range. */

	/* General errors. */
	KNOT_ERROR = -10000,  /*!< General error. */
	KNOT_ENOTRUNNING,     /*!< Resource is not running. */
	KNOT_EPARSEFAIL,      /*!< Parser fail. */
	KNOT_ENOIPV6,         /*!< No IPv6 support. */
	KNOT_EEXPIRED,        /*!< Resource is expired. */
	KNOT_EUPTODATE,       /*!< Zone is up-to-date. */
	KNOT_EFEWDATA,        /*!< Not enough data to parse. */
	KNOT_ESPACE,          /*!< Not enough space provided. */
	KNOT_EMALF,           /*!< Malformed data. */
	KNOT_ECRYPTO,         /*!< Error in crypto library. */
	KNOT_ENSEC3PAR,       /*!< Missing or wrong NSEC3PARAM record. */
	KNOT_ENSEC3CHAIN,     /*!< Missing or wrong NSEC3 chain in the zone. */
	KNOT_EOUTOFZONE,      /*!< Domain name does not belong to the zone. */
	KNOT_EHASH,           /*!< Error in hash table. */
	KNOT_EZONEINVAL,      /*!< Invalid zone file. */
	KNOT_EZONENOENT,      /*!< Zone file not found. */
	KNOT_ENOZONE,         /*!< No such zone found. */
	KNOT_ENONODE,         /*!< No such node in zone found. */
	KNOT_ENORRSET,        /*!< No such RRSet found. */
	KNOT_EDNAMEPTR,       /*!< Domain name pointer larger than allowed. */
	KNOT_EPAYLOAD,        /*!< Payload in OPT RR larger than max wire size. */
	KNOT_ECRC,            /*!< Wrong dump CRC. */
	KNOT_EPREREQ,         /*!< UPDATE prerequisity not met. */
	KNOT_ENOXFR,          /*!< Transfer was not sent. */
	KNOT_ENOIXFR,         /*!< Transfer is not IXFR (is in AXFR format). */
	KNOT_EXFRREFUSED,     /*!< Zone transfer refused by the server. */
	KNOT_EDENIED,         /*!< Not allowed. */
	KNOT_ECONN,           /*!< Connection reset. */
	KNOT_EIXFRSPACE,      /*!< IXFR reply did not fit in. */
	KNOT_ECNAME,          /*!< CNAME loop found in zone. */
	KNOT_ENODIFF,         /*!< No zone diff can be created. */
	KNOT_EDSDIGESTLEN,    /*!< DS digest length does not match digest type. */
	KNOT_ENOTSIG,         /*!< Expected a TSIG or SIG(0). */
	KNOT_ELIMIT,          /*!< Exceeded response rate limit. */
	KNOT_EWRITABLE,       /*!< File is not writable. */

	/* Control states. */
	KNOT_CTL_STOP,        /*!< Stop requested. */

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

	/* NSEC3 errors. */
	KNOT_NSEC3_ECOMPUTE_HASH
};

/*! \brief Table linking error messages to error codes. */
extern const error_table_t knot_error_msgs[];

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
static inline const char *knot_strerror(int code)
{
	return error_to_str((const error_table_t*)knot_error_msgs, code);
}

/*!
 * \brief errno mapper that automatically prepends fallback value.
 *
 * \see map_errno()
 *
 * \param err POSIX errno.
 * \param ... List of handled codes.
 *
 * \return Mapped error code.
 */
#define knot_map_errno(err...) map_errno(KNOT_ERROR, err);

#endif /* _KNOTD_COMMON_ERRCODE_H_ */

/*! @} */
