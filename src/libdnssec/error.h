/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
	DNSSEC_EOK = 0,

	DNSSEC_ENOMEM = -ENOMEM,
	DNSSEC_EINVAL = -EINVAL,
	DNSSEC_ENOENT = -ENOENT,

	DNSSEC_ERROR_MIN = -1500,

	DNSSEC_ERROR = DNSSEC_ERROR_MIN,
	DNSSEC_NOT_IMPLEMENTED_ERROR,
	DNSSEC_MALFORMED_DATA,
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
	DNSSEC_INVALID_KEY_NAME,

	DNSSEC_NO_PUBLIC_KEY,
	DNSSEC_NO_PRIVATE_KEY,
	DNSSEC_KEY_ALREADY_PRESENT,

	DNSSEC_SIGN_INIT_ERROR,
	DNSSEC_SIGN_ERROR,
	DNSSEC_INVALID_SIGNATURE,

	DNSSEC_INVALID_NSEC3_ALGORITHM,
	DNSSEC_NSEC3_HASHING_ERROR,

	DNSSEC_INVALID_DS_ALGORITHM,
	DNSSEC_DS_HASHING_ERROR,

	DNSSEC_KEYSTORE_INVALID_CONFIG,

	DNSSEC_P11_FAILED_TO_LOAD_MODULE,
	DNSSEC_P11_TOO_MANY_MODULES,
	DNSSEC_P11_TOKEN_NOT_AVAILABLE,

	DNSSEC_HASH_ERROR,

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
