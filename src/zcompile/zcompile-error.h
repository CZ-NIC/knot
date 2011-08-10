/*!
 * \file zcompile-error.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup zoneparser
 * @{
 */

#ifndef _KNOTD_ZCOMPILE_ERROR_H_
#define _KNOTD_ZCOMPILE_ERROR_H_

#include "common/errors.h"

/*!
 * \brief Error codes used in the server.
 *
 * Some viable errors are directly mapped
 * to libc errno codes.
 */
enum knot_zcompile_error {

	/* Directly mapped error codes. */
	KNOTDZCOMPILE_EOK = 0,
	KNOTDZCOMPILE_ENOMEM = -ENOMEM, /*!< \brief Out of memory. */
	KNOTDZCOMPILE_EINVAL = -EINVAL, /*!< \brief Invalid parameter passed. */
	/*!
	 * \brief Parameter not supported.
	 */
	KNOTDZCOMPILE_ENOTSUP = -ENOTSUP,
	KNOTDZCOMPILE_EBUSY = -EBUSY, /*!< \brief Requested resource is busy. */
	/*!
	 * \brief OS lacked necessary resources.
	 */
	KNOTDZCOMPILE_EAGAIN = -EAGAIN,
	KNOTDZCOMPILE_EACCES = -EACCES, /*!< \brief Permission is denied. */
	/*!
	 * \brief Connection is refused.
	 */
	KNOTDZCOMPILE_ECONNREFUSED = -ECONNREFUSED,
	KNOTDZCOMPILE_EISCONN = -EISCONN, /*!< \brief Already connected. */
	/*!
	 * \brief Address already in use.
	 */
	KNOTDZCOMPILE_EADDRINUSE = -EADDRINUSE,
	KNOTDZCOMPILE_ENOENT = -ENOENT, /*!< \brief Resource not found. */
	KNOTDZCOMPILE_ERANGE = -ERANGE, /*!< \brief Value is out of range. */

	/* Custom error codes. */
	KNOTDZCOMPILE_ERROR = -16384, /*!< \brief Generic error. */
	KNOTDZCOMPILE_ESYNT, /*!< \brief Syntax error. */
	KNOTDZCOMPILE_EBADNODE, /*!< \brief Node error. */
	KNOTDZCOMPILE_EBRDATA, /*!< \brief RDATA error. */
	KNOTDZCOMPILE_EBADSOA, /*!< \brief SOA owner error. */
	KNOTDZCOMPILE_ESOA, /*!< \brief Multiple SOA records. */

	KNOTDZCOMPILE_EZONEINVAL, /*!< \brief Invalid zone file. */
	KNOTDZCOMPILE_EPARSEFAIL, /*!< \brief Parser fail. */
	KNOTDZCOMPILE_ENOIPV6, /*! \brief No IPv6 support. */

	KNOTDZCOMPILE_ERROR_COUNT = 22
};

typedef enum knot_zcompile_error knot_zcompile_error_t;

/*! \brief Table linking error messages to error codes. */
extern const error_table_t knot_zcompile_error_msgs[KNOTDZCOMPILE_ERROR_COUNT];

#endif /* _KNOTD_ZCOMPILE_ERROR_H_ */

/*! @} */
