/*!
 * \file error.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup libknot
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

#ifndef _KNOT_ERROR_H_
#define _KNOT_ERROR_H_

#include "common/errors.h"

/*! \brief Error codes used in the library. */
enum knot_error {
	KNOT_EOK = 0,         /*!< OK */
	
	/* TSIG errors. */
	KNOT_TSIG_EBADSIG = -16, /*!< Failed to verify TSIG MAC. */
	KNOT_TSIG_EBADKEY = -17, /*!< TSIG key not recognized or invalid. */
	KNOT_TSIG_EBADTIME = -18,/*!< TSIG signing time out of range. */
	
	/* General errors. */
	KNOT_ERROR = -10000,  /*!< General error. */
	KNOT_ENOMEM,          /*!< Not enough memory. */
	KNOT_ENOTSUP,         /*!< Operation not supported. */
	KNOT_EAGAIN,          /*!< OS lacked necessary resources. */
	KNOT_ERANGE,          /*!< Value is out of range. */
	KNOT_EBADARG,         /*!< Wrong argument supported. */
	KNOT_EFEWDATA,        /*!< Not enough data to parse. */
	KNOT_ESPACE,          /*!< Not enough space provided. */
	KNOT_EMALF,           /*!< Malformed data. */
	KNOT_ECRYPTO,         /*!< Error in crypto library. */
	KNOT_ENSEC3PAR,       /*!< Missing or wrong NSEC3PARAM record. */
	KNOT_EBADZONE,        /*!< Domain name does not belong to the zone. */
	KNOT_EHASH,           /*!< Error in hash table. */
	KNOT_EZONEIN,         /*!< Error inserting zone. */
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
	KNOT_ECONN,           /*!< Connection reset. */
	KNOT_ERROR_COUNT = 30
};

/*! \brief Table linking error messages to error codes. */
extern const error_table_t knot_error_msgs[KNOT_ERROR_COUNT];

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

#endif /* _KNOT_ERROR_H_ */

/*! @} */
