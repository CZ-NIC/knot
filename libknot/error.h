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

#ifndef _KNOT_ERROR_H_
#define _KNOT_ERROR_H_

#include "common/errors.h"

/*! \brief Error codes used in the library. */
enum knot_error {
	KNOT_EOK = 0,         /*!< OK */
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
	KNOT_EDNAMEPTR,       /*!< Domain name pointer larger than allowed. */
	KNOT_EPAYLOAD,        /*!< Payload in OPT RR larger than max wire size. */
	KNOT_ECRC,            /*!< Wrong dump CRC. */
	KNOT_ERROR_COUNT = 18
};

/*! \brief Table linking error messages to error codes. */
extern const error_table_t knot_error_msgs2[KNOT_ERROR_COUNT];

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
static inline const char *knot_strerror2(int code)
{
	return error_to_str((const error_table_t*)knot_error_msgs2, code);
}

#endif /* _KNOT_ERROR_H_ */

/*! @} */
