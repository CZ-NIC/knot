/*!
 * \file error.h
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _KNOT_ZCOMPILE_ERROR_H_
#define _KNOT_ZCOMPILE_ERROR_H_
#include <errno.h>

/*!
 * \brief Error codes used in the server.
 *
 * Some viable errors are directly mapped
 * to libc errno codes.
 */
enum knot_zcompile_error {

	/* Directly mapped error codes. */
	KNOT_ZCOMPILE_EOK = 0,
	KNOT_ZCOMPILE_ENOMEM = -ENOMEM, /*!< \brief Out of memory. */
	KNOT_ZCOMPILE_EINVAL = -EINVAL, /*!< \brief Invalid parameter passed. */
	/*!
	 * \brief Parameter not supported.
	 */
	KNOT_ZCOMPILE_ENOTSUP = -ENOTSUP,
	KNOT_ZCOMPILE_EBUSY = -EBUSY, /*!< \brief Requested resource is busy. */
	/*!
	 * \brief OS lacked necessary resources.
	 */
	KNOT_ZCOMPILE_EAGAIN = -EAGAIN,
	KNOT_ZCOMPILE_EACCES = -EACCES, /*!< \brief Permission is denied. */
	/*!
	 * \brief Connection is refused.
	 */
	KNOT_ZCOMPILE_ECONNREFUSED = -ECONNREFUSED,
	KNOT_ZCOMPILE_EISCONN = -EISCONN, /*!< \brief Already connected. */
	/*!
	 * \brief Address already in use.
	 */
	KNOT_ZCOMPILE_EADDRINUSE = -EADDRINUSE,
	KNOT_ZCOMPILE_ENOENT = -ENOENT, /*!< \brief Resource not found. */
	KNOT_ZCOMPILE_ERANGE = -ERANGE, /*!< \brief Value is out of range. */

	/* Custom error codes. */
	KNOT_ZCOMPILE_ERROR = -16384, /*!< \brief Generic error. */
	KNOT_ZCOMPILE_ESEMERR,
	KNOT_ZCOMPILE_ESYNERR,
	KNOT_ZCOMPILE_EBADNODE,
	KNOT_ZCOMPILE_EBRDATA,
	KNOT_ZCOMPILE_ESOA,

	KNOT_ZCOMPILE_EZONEINVAL, /*!< \brief Invalid zone file. */
	KNOT_ZCOMPILE_EPARSEFAIL, /*!< \brief Parser fail. */
	KNOT_ZCOMPILE_ENOIPV6 /*! \brief No IPv6 support. */
};

typedef enum knot_zcompile_error knot_zcompile_error_t;

/*!
 * \brief Returns error message for the given error code.
 *
 * \param errno Error code.
 *
 * \return String containing the error message.
 */
const char *knot_zcompile_strerror(int errno);

/*!
 * \brief Safe errno mapper that automatically appends sentinel value.
 * \see knot_map_errno_f
 *
 * \param err POSIX errno.
 * \param ... List of handled codes.
 *
 * \return Mapped error code.
 */
#define knot_zcompile_map_errno(err...) _knot_zcompile_map_errno(err, KNOT_ZONEPARSER_ERROR);

/*!
 * \brief Returns a mapped POSIX errcode.
 *
 * \warning Last error must be KNOT_ZCOMPILE_ERROR, it serves as a fallback and
 *          a sentinel value as well. Use knot_map_errno() instead.
 *
 * \param arg0 First mandatory argument.
 * \param ... List of handled codes.
 *
 * \return Mapped error code.
 */
int _knot_map_errno(int arg0, ...);

#endif /* _KNOT_ZCOMPILE_ERROR_H_ */

/*! @} */
