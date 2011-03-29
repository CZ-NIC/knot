/*!
 * \file error.h
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

/*!
 * \brief Error codes used in the server.
 *
 * Some viable errors are directly mapped
 * to libc errno codes.
 */
typedef enum knot_error_t {
	KNOT_EOK = 0,
	KNOT_ENOMEM = ENOMEM, /*!< \brief Out of memory. */
	KNOT_EINVAL = EINVAL, /*!< \brief Invalid parameter passed. */
	KNOT_ENOTSUP = ENOTSUP, /*!< \brief Parameter not supported. */
	KNOT_EBUSY = EBUSY, /*!< \brief Requested resource is busy. */
	KNOT_EAGAIN = EAGAIN, /*!< \brief OS lacked necessary resources. */
	KNOT_ERROR = -16384 /*!< \brief Generic error. */
} knot_error_t;

/*!
 * \brief Returns error message for the given error code.
 *
 * \param errno Error code.
 *
 * \return String containing the error message.
 */
const char *knot_strerror(int errno);

#endif /* _KNOT_ERROR_H_ */

/*! @} */
