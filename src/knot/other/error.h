/*!
 * \file error.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _KNOT_ERROR_H_
#define _KNOT_ERROR_H_

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
	KNOT_EOK = 0,
	KNOT_ENOMEM = -ENOMEM, /*!< \brief Out of memory. */
	KNOT_EINVAL = -EINVAL, /*!< \brief Invalid parameter passed. */
	KNOT_ENOTSUP = -ENOTSUP, /*!< \brief Parameter not supported. */
	KNOT_EBUSY = -EBUSY, /*!< \brief Requested resource is busy. */
	KNOT_EAGAIN = -EAGAIN, /*!< \brief OS lacked necessary resources. */
	KNOT_EACCES = -EACCES, /*!< \brief Permission is denied. */
	KNOT_ECONNREFUSED = -ECONNREFUSED, /*!< \brief Connection is refused. */
	KNOT_EISCONN = -EISCONN, /*!< \brief Already connected. */
	KNOT_EADDRINUSE = -EADDRINUSE, /*!< \brief Address already in use. */
	KNOT_ENOENT = -ENOENT, /*!< \brief Resource not found. */
	KNOT_ERANGE = -ERANGE, /*!< \brief Value is out of range. */

	/* Custom error codes. */
	KNOT_ERROR = -16384, /*!< \brief Generic error. */
	KNOT_EADDRINVAL, /*!< \brief Invalid address. */
	KNOT_EZONEINVAL, /*!< \brief Invalid zone file. */
	KNOT_ENOTRUNNING, /*!< \brief Resource is not running. */
	KNOT_EPARSEFAIL, /*!< \brief Parser fail. */
	KNOT_ENOIPV6, /*! \brief No IPv6 support. */

	KNOT_ERROR_COUNT = 19
};

const _knot_error_table_t knot_error_msgs[KNOT_ERROR_COUNT];

/*!
 * \brief Returns error message for the given error code.
 *
 * \param errno Error code.
 *
 * \return String containing the error message.
 */
inline const char *knot_strerror(int errno)
{
	return _knot_strerror(&knot_error_msgs, errno);
}

/*!
 * \brief errno mapper that automatically prepends fallback value.
 *
 * \see _knot_map_errno()
 *
 * \param err POSIX errno.
 * \param ... List of handled codes.
 *
 * \return Mapped error code.
 */
#define knot_map_errno(err...) _knot_map_errno(KNOT_ERROR, err);

///*!
// * \brief Returns a mapped POSIX errcode.
// *
// * \warning Last error must be KNOT_ERROR, it serves as a fallback and
// *          a sentinel value as well. Use knot_map_errno() instead.
// *
// * \param arg0 First mandatory argument.
// * \param ... List of handled codes.
// * \return Mapped error code.
// */
//int _knot_map_errno(int arg0, ...);

#endif /* _KNOT_ERROR_H_ */

/*! @} */
