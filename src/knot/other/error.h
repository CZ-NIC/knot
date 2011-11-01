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
/*!
 * \file other/error.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _KNOTD__ERROR_H_
#define _KNOTD__ERROR_H_

#include <errno.h>

#include "common/errors.h"

/*!
 * \brief Error codes used in the server.
 *
 * Some viable errors are directly mapped
 * to libc errno codes.
 */
enum knot_error_t {

	/* Directly mapped error codes. */
	KNOTD_EOK = 0,
	KNOTD_ENOMEM = -ENOMEM, /*!< \brief Out of memory. */
	KNOTD_EINVAL = -EINVAL, /*!< \brief Invalid parameter passed. */
	KNOTD_ENOTSUP = -ENOTSUP, /*!< \brief Parameter not supported. */
	KNOTD_EBUSY = -EBUSY, /*!< \brief Requested resource is busy. */
	KNOTD_EAGAIN = -EAGAIN, /*!< \brief OS lacked necessary resources. */
	KNOTD_EACCES = -EACCES, /*!< \brief Permission is denied. */
	KNOTD_ECONNREFUSED = -ECONNREFUSED, /*!< \brief Connection is refused. */
	KNOTD_EISCONN = -EISCONN, /*!< \brief Already connected. */
	KNOTD_EADDRINUSE = -EADDRINUSE, /*!< \brief Address already in use. */
	KNOTD_ENOENT = -ENOENT, /*!< \brief Resource not found. */
	KNOTD_ERANGE = -ERANGE, /*!< \brief Value is out of range. */

	/* Custom error codes. */
	KNOTD_ERROR = -16384, /*!< \brief Generic error. */
	KNOTD_EZONEINVAL, /*!< \brief Invalid zone file. */
	KNOTD_ENOTRUNNING, /*!< \brief Resource is not running. */
	KNOTD_EPARSEFAIL, /*!< \brief Parser fail. */
	KNOTD_ENOIPV6, /*!< \brief No IPv6 support. */
	KNOTD_EMALF, /*!< \brief Malformed data. */
	KNOTD_ESPACE, /*!< \brief Not enough space provided. */
	KNOTD_EEXPIRED, /*!< \brief Resource is expired. */

	KNOTD_ERROR_COUNT = 21
};

/*! \brief Table linking error messages to error codes. */
extern const error_table_t knotd_error_msgs[KNOTD_ERROR_COUNT];

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
static inline const char *knotd_strerror(int code)
{
	return error_to_str((const error_table_t*)knotd_error_msgs, code);
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
#define knot_map_errno(err...) map_errno(KNOTD_ERROR, err);

#endif /* _KNOTD__ERROR_H_ */

/*! @} */
