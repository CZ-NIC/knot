/*!
 * \file dnslib/error.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ERROR_H_
#define _KNOT_DNSLIB_ERROR_H_

#include "common/errors.h"

/*! \brief Error codes used in the dnslib library. */
enum dnslib_error {
	DNSLIB_EOK = 0,         /*!< OK */
	DNSLIB_ERROR = -10000,  /*!< General dnslib error. */
	DNSLIB_ENOMEM,          /*!< Not enough memory. */
	DNSLIB_EBADARG,         /*!< Wrong argument supported. */
	DNSLIB_EFEWDATA,        /*!< Not enough data to parse. */
	DNSLIB_ESPACE,          /*!< Not enough space provided. */
	DNSLIB_EMALF,           /*!< Malformed data. */
	DNSLIB_ECRYPTO,         /*!< Error in crypto library. */
	DNSLIB_ENSEC3PAR,       /*!< Missing or wrong NSEC3PARAM record. */
	DNSLIB_EBADZONE,        /*!< Domain name does not belong to the zone. */
	DNSLIB_EHASH,           /*!< Error in hash table. */
	DNSLIB_EZONEIN,         /*!< Error inserting zone. */
	DNSLIB_ENOZONE,         /*!< No such zone found. */
	DNSLIB_EDNAMEPTR,       /*!< Domain name pointer larger than allowed. */
	DNSLIB_EPAYLOAD,        /*!< Payload in OPT RR larger than max wire size. */
	DNSLIB_ECRC,            /*!< Wrong dump CRC. */
	DNSLIB_ERROR_COUNT = 17
};

/*! \brief Table linking error messages to error codes. */
const error_table_t dnslib_error_msgs[DNSLIB_ERROR_COUNT];

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
static inline const char *dnslib_strerror(int code)
{
	return error_to_str((const error_table_t*)dnslib_error_msgs, code);
}

#endif /* _KNOT_DNSLIB_ERROR_H_ */

/*! @} */
