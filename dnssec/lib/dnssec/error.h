#pragma once

#include <errno.h>

#define errno2error(errno) (-(100 + (errno)))

/*!
 * Library error codes.
 */
enum dnssec_error {
	DNSSEC_EOK = 0,

	DNSSEC_ENOMEM = errno2error(ENOMEM),
	DNSSEC_EINVAL = errno2error(EINVAL),

	DNSSEC_ERROR = -1000,
	DNSSEC_NOT_IMPLEMENTED_ERROR,
	DNSSEC_MALFORMED_DATA,
	DNSSEC_OUT_OF_RANGE,
	DNSSEC_NOT_FOUND,

	DNSSEC_PKCS8_IMPORT_ERROR,
	DNSSEC_KEY_EXPORT_ERROR,
	DNSSEC_KEY_IMPORT_ERROR,
	DNSSEC_KEY_GENERATE_ERROR,

	DNSSEC_INVALID_PUBLIC_KEY,
	DNSSEC_INVALID_PRIVATE_KEY,
	DNSSEC_INVALID_KEY_ALGORITHM,
	DNSSEC_INVALID_KEY_SIZE,
	DNSSEC_INVALID_KEY_ID,

	DNSSEC_NO_PUBLIC_KEY,
	DNSSEC_NO_PRIVATE_KEY,
	DNSSEC_KEY_ALREADY_PRESENT,

	DNSSEC_SIGN_INIT_ERROR,
	DNSSEC_SIGN_ERROR,
	DNSSEC_INVALID_SIGNATURE,
	DNSSEC_INVALID_NSEC3_ALGORITHM,
	DNSSEC_NSEC3_HASHING_ERROR,

	DNSSEC_CONFIG_MALFORMED,
	DNSSEC_CONFIG_TOO_MANY_KEYS,
	DNSSEC_CONFIG_INVALID_KEY_ID,
};

/*!
 * Translate error code to error message.
 *
 * \param error  Error code.
 *
 * \return Statically allocated error message string.
 */
const char *dnssec_strerror(int error);

/*!
 * Convert errno to error code.
 */
static inline int dnssec_errno_to_error(int ecode)
{
	return errno2error(ecode);
}

#undef errno2error
