/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup error
 *
 * \brief Error codes and error reporting.
 *
 * The module defines all error codes used in the library, and functions
 * to convert the error codes to sensible error strings.
 *
 * @{
 */

#pragma once

#include <errno.h>

/*!
 * Library error codes.
 */
enum dnssec_error {
	KNOT_EOK = 0,

	KNOT_ENOMEM = -ENOMEM,
	KNOT_EINVAL = -EINVAL,
	KNOT_ENOENT = -ENOENT,

	DNSSEC_ERROR_MIN = -1500,

	KNOT_ERROR = DNSSEC_ERROR_MIN,
	KNOT_ENOTSUP,
	KNOT_EMALF,
	KNOT_ENOENT,

	KNOT_KEY_EIMPORT,
	KNOT_KEY_EEXPORT,
	KNOT_KEY_EIMPORT,
	KNOT_KEY_EGENERATE,

	KNOT_INVALID_PUBLIC_KEY,
	DNSSEC_INVALID_PRIVATE_KEY,
	KNOT_INVALID_KEY_ALGORITHM,
	KNOT_INVALID_KEY_SIZE,
	KNOT_INVALID_KEY_ID,
	KNOT_INVALID_KEY_NAME,

	KNOT_NO_PUBLIC_KEY,
	KNOT_NO_PRIVATE_KEY,
	KNOT_EEXIST,

	KNOT_ECRYPTO,
	DNSSEC_SIGN_ERROR,
	DNSSEC_INVALID_SIGNATURE,

	KNOT_EALGORITHM,
	DNSSEC_NSEC3_HASHING_ERROR,

	KNOT_EALGORITHM,
	DNSSEC_DS_HASHING_ERROR,

	DNSSEC_KEYSTORE_INVALID_CONFIG,

	DNSSEC_P11_FAILED_TO_LOAD_MODULE,
	DNSSEC_P11_TOO_MANY_MODULES,
	DNSSEC_P11_TOKEN_NOT_AVAILABLE,

	KNOT_EALGORITHM,
	DNSSEC_DIGEST_ERROR,

	DNSSEC_ERROR_MAX = -1001
};

/*!
 * Translate error code to error message.
 *
 * \param error  Error code.
 *
 * \return Statically allocated error message string or NULL if unknown.
 */
const char *dnssec_strerror(int error);

/*!
 * Convert errno value to DNSSEC error code.
 */
static inline int dnssec_errno_to_error(int ecode)
{
	return -ecode;
}

/*! @} */
