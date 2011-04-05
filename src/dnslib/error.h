/*!
 * \file error.h
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

/*! \brief Error codes used in the dnslib library. */
enum dnslib_error {
	DNSLIB_EOK = 0,
	DNSLIB_ERROR = -10000,
	DNSLIB_ENOMEM,
	DNSLIB_EBADARG,
	DNSLIB_EFEWDATA,
	DNSLIB_ESPACE,
	DNSLIB_EMALF,
	DNSLIB_ECRYPTO,
	DNSLIB_ENSEC3PAR,
	DNSLIB_EBADZONE,
	DNSLIB_EHASH,
	DNSLIB_EZONEIN,
	DNSLIB_ENOZONE

};

/*! \brief Error codes used in the dnslib library. */
typedef enum dnslib_error dnslib_error_t;

/*!
 * \brief Returns error message for the given error code.
 *
 * \param errno Error code.
 *
 * \return String containing the error message.
 */
const char *dnslib_strerror(dnslib_error_t errno);

#endif /* _KNOT_DNSLIB_ERROR_H_ */

/*! @} */
