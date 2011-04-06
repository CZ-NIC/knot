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

#include "common/errors.h"

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
	KNOT_ZCOMPILE_ESYNT, /*!< \brief Syntax error. */
	KNOT_ZCOMPILE_EBADNODE, /*!< \brief Node error. */
	KNOT_ZCOMPILE_EBRDATA, /*!< \brief RDATA error. */
	KNOT_ZCOMPILE_EBADSOA, /*!< \brief SOA owner error. */
	KNOT_ZCOMPILE_ESOA, /*!< \brief Multiple SOA records. */

	KNOT_ZCOMPILE_EZONEINVAL, /*!< \brief Invalid zone file. */
	KNOT_ZCOMPILE_EPARSEFAIL, /*!< \brief Parser fail. */
	KNOT_ZCOMPILE_ENOIPV6, /*! \brief No IPv6 support. */

	KNOT_ZCOMPILE_ERROR_COUNT = 22
};

typedef enum knot_zcompile_error knot_zcompile_error_t;

/*! \brief Table linking error messages to error codes. */
const error_table_t knot_zcompile_error_msgs[KNOT_ZCOMPILE_ERROR_COUNT];

#endif /* _KNOT_ZCOMPILE_ERROR_H_ */

/*! @} */
