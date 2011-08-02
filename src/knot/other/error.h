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

#ifndef _KNOTDERROR_H_
#define _KNOTDERROR_H_

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
	KNOTDEOK = 0,
	KNOTDENOMEM = -ENOMEM, /*!< \brief Out of memory. */
	KNOTDEINVAL = -EINVAL, /*!< \brief Invalid parameter passed. */
	KNOTDENOTSUP = -ENOTSUP, /*!< \brief Parameter not supported. */
	KNOTDEBUSY = -EBUSY, /*!< \brief Requested resource is busy. */
	KNOTDEAGAIN = -EAGAIN, /*!< \brief OS lacked necessary resources. */
	KNOTDEACCES = -EACCES, /*!< \brief Permission is denied. */
	KNOTDECONNREFUSED = -ECONNREFUSED, /*!< \brief Connection is refused. */
	KNOTDEISCONN = -EISCONN, /*!< \brief Already connected. */
	KNOTDEADDRINUSE = -EADDRINUSE, /*!< \brief Address already in use. */
	KNOTDENOENT = -ENOENT, /*!< \brief Resource not found. */
	KNOTDERANGE = -ERANGE, /*!< \brief Value is out of range. */

	/* Custom error codes. */
	KNOTDERROR = -16384, /*!< \brief Generic error. */
	KNOTDEZONEINVAL, /*!< \brief Invalid zone file. */
	KNOTDENOTRUNNING, /*!< \brief Resource is not running. */
	KNOTDEPARSEFAIL, /*!< \brief Parser fail. */
	KNOTDENOIPV6, /*!< \brief No IPv6 support. */
	KNOTDEMALF, /*!< \brief Malformed data. */
	KNOTDESPACE, /*!< \brief Not enough space provided. */

	KNOTDERROR_COUNT = 20
};

/*! \brief Table linking error messages to error codes. */
extern const error_table_t knot_error_msgs[KNOTDERROR_COUNT];

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
#define knot_map_errno(err...) map_errno(KNOTDERROR, err);

#endif /* _KNOTDERROR_H_ */

/*! @} */
